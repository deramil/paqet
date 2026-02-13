package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/pkg/hash"
	"paqet/internal/pkg/iterator"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type TCPF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.RWMutex
}

var (
	tcpOptMSSData         = []byte{0x05, 0xb4}
	tcpOptWindowScaleData = []byte{8}
)

type SendHandle struct {
	handle      *pcap.Handle
	txProto     string
	srcIPv4     net.IP
	srcIPv4RHWA net.HardwareAddr
	srcIPv6     net.IP
	srcIPv6RHWA net.HardwareAddr
	srcPort     uint16
	bufOptions  gopacket.SerializeOptions
	time        uint32
	tsCounter   uint32
	tcpF        TCPF
	ethPool     sync.Pool
	ipv4Pool    sync.Pool
	ipv6Pool    sync.Pool
	tcpPool     sync.Pool
	udpPool     sync.Pool
	bufPool     sync.Pool
}

func NewSendHandle(cfg *conf.Network) (*SendHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionOut); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction out: %v", err)
		}
	}

	sh := &SendHandle{
		handle:     handle,
		txProto:    cfg.TxProto,
		srcPort:    uint16(cfg.Port),
		bufOptions: gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		tcpF:       TCPF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		time:       uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		ethPool: sync.Pool{New: func() any {
			return &layers.Ethernet{SrcMAC: cfg.Interface.HardwareAddr}
		}},
		ipv4Pool: sync.Pool{New: func() any { return &layers.IPv4{} }},
		ipv6Pool: sync.Pool{New: func() any { return &layers.IPv6{} }},
		tcpPool:  sync.Pool{New: func() any { return &layers.TCP{} }},
		udpPool:  sync.Pool{New: func() any { return &layers.UDP{} }},
		bufPool: sync.Pool{New: func() any {
			return gopacket.NewSerializeBuffer()
		}},
	}
	if cfg.IPv4.Addr != nil {
		sh.srcIPv4 = cfg.IPv4.Addr.IP
		sh.srcIPv4RHWA = cfg.IPv4.Router
	}
	if cfg.IPv6.Addr != nil {
		sh.srcIPv6 = cfg.IPv6.Addr.IP
		sh.srcIPv6RHWA = cfg.IPv6.Router
	}
	return sh, nil
}

func (h *SendHandle) ipProto() layers.IPProtocol {
	if h.txProto == "udp" {
		return layers.IPProtocolUDP
	}
	return layers.IPProtocolTCP
}

func (h *SendHandle) buildIPv4Header(dstIP net.IP) *layers.IPv4 {
	ip := h.ipv4Pool.Get().(*layers.IPv4)
	*ip = layers.IPv4{Version: 4, IHL: 5, TOS: 184, TTL: 64, Flags: layers.IPv4DontFragment, Protocol: h.ipProto(), SrcIP: h.srcIPv4, DstIP: dstIP}
	return ip
}

func (h *SendHandle) buildIPv6Header(dstIP net.IP) *layers.IPv6 {
	ip := h.ipv6Pool.Get().(*layers.IPv6)
	*ip = layers.IPv6{Version: 6, TrafficClass: 184, HopLimit: 64, NextHeader: h.ipProto(), SrcIP: h.srcIPv6, DstIP: dstIP}
	return ip
}

func ensureTCPOptions(tcp *layers.TCP, syn bool) {
	if syn {
		if cap(tcp.Options) < 5 {
			tcp.Options = make([]layers.TCPOption, 5)
		} else {
			tcp.Options = tcp.Options[:5]
		}
		tcp.Options[0] = layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: tcpOptMSSData}
		tcp.Options[1] = layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2}
		tcp.Options[2] = layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10}
		tcp.Options[3] = layers.TCPOption{OptionType: layers.TCPOptionKindNop}
		tcp.Options[4] = layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: tcpOptWindowScaleData}
	} else {
		if cap(tcp.Options) < 3 {
			tcp.Options = make([]layers.TCPOption, 3)
		} else {
			tcp.Options = tcp.Options[:3]
		}
		tcp.Options[0] = layers.TCPOption{OptionType: layers.TCPOptionKindNop}
		tcp.Options[1] = layers.TCPOption{OptionType: layers.TCPOptionKindNop}
		tcp.Options[2] = layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10}
	}
	if len(tcp.Options[2].OptionData) != 8 {
		tcp.Options[2].OptionData = make([]byte, 8)
	}
}

func (h *SendHandle) buildTCPHeader(dstPort uint16, f conf.TCPF) *layers.TCP {
	tcp := h.tcpPool.Get().(*layers.TCP)
	*tcp = layers.TCP{SrcPort: layers.TCPPort(h.srcPort), DstPort: layers.TCPPort(dstPort), FIN: f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS, Window: 65535}

	counter := atomic.AddUint32(&h.tsCounter, 1)
	tsVal := h.time + (counter >> 3)
	if f.SYN {
		ensureTCPOptions(tcp, true)
		binary.BigEndian.PutUint32(tcp.Options[2].OptionData[0:4], tsVal)
		binary.BigEndian.PutUint32(tcp.Options[2].OptionData[4:8], 0)
		tcp.Seq = 1 + (counter & 0x7)
		tcp.Ack = 0
		if f.ACK {
			tcp.Ack = tcp.Seq + 1
		}
	} else {
		tsEcr := tsVal - (counter%200 + 50)
		ensureTCPOptions(tcp, false)
		binary.BigEndian.PutUint32(tcp.Options[2].OptionData[0:4], tsVal)
		binary.BigEndian.PutUint32(tcp.Options[2].OptionData[4:8], tsEcr)
		seq := h.time + (counter << 7)
		tcp.Seq = seq
		tcp.Ack = seq - (counter & 0x3FF) + 1400
	}
	return tcp
}

func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr) error {
	buf := h.bufPool.Get().(gopacket.SerializeBuffer)
	ethLayer := h.ethPool.Get().(*layers.Ethernet)

	dstIP := addr.IP
	dstPort := uint16(addr.Port)
	f := h.getClientTCPF(dstIP, dstPort)

	var ipLayer gopacket.SerializableLayer
	var trLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		ip := h.buildIPv4Header(dstIP)
		ipLayer = ip
		if h.txProto == "udp" {
			udp := h.udpPool.Get().(*layers.UDP)
			*udp = layers.UDP{SrcPort: layers.UDPPort(h.srcPort), DstPort: layers.UDPPort(dstPort)}
			udp.SetNetworkLayerForChecksum(ip)
			trLayer = udp
		} else {
			tcp := h.buildTCPHeader(dstPort, f)
			tcp.SetNetworkLayerForChecksum(ip)
			trLayer = tcp
		}
		ethLayer.DstMAC = h.srcIPv4RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv4
	} else {
		ip := h.buildIPv6Header(dstIP)
		ipLayer = ip
		if h.txProto == "udp" {
			udp := h.udpPool.Get().(*layers.UDP)
			*udp = layers.UDP{SrcPort: layers.UDPPort(h.srcPort), DstPort: layers.UDPPort(dstPort)}
			udp.SetNetworkLayerForChecksum(ip)
			trLayer = udp
		} else {
			tcp := h.buildTCPHeader(dstPort, f)
			tcp.SetNetworkLayerForChecksum(ip)
			trLayer = tcp
		}
		ethLayer.DstMAC = h.srcIPv6RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}

	err := gopacket.SerializeLayers(buf, h.bufOptions, ethLayer, ipLayer, trLayer, gopacket.Payload(payload))
	if err == nil {
		err = h.handle.WritePacketData(buf.Bytes())
	}

	if tcp, ok := trLayer.(*layers.TCP); ok {
		h.tcpPool.Put(tcp)
	} else if udp, ok := trLayer.(*layers.UDP); ok {
		h.udpPool.Put(udp)
	}
	if ip, ok := ipLayer.(*layers.IPv4); ok {
		h.ipv4Pool.Put(ip)
	} else if ip, ok := ipLayer.(*layers.IPv6); ok {
		h.ipv6Pool.Put(ip)
	}
	buf.Clear()
	h.bufPool.Put(buf)
	h.ethPool.Put(ethLayer)

	return err
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	h.tcpF.mu.RLock()
	defer h.tcpF.mu.RUnlock()
	if ff := h.tcpF.clientTCPF[hash.IPAddr(dstIP, dstPort)]; ff != nil {
		return ff.Next()
	}
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a := *addr.(*net.UDPAddr)
	h.tcpF.mu.Lock()
	h.tcpF.clientTCPF[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
