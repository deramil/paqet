//go:build pcap

package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type RecvHandle struct {
	handle  *pcap.Handle
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
	eth     layers.Ethernet
	ipv4    layers.IPv4
	ipv6    layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	payload gopacket.Payload
}

func NewRecvHandle(cfg *conf.Network) (*RecvHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("%s and dst port %d", cfg.RxProto, cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	r := &RecvHandle{handle: handle}
	r.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&r.eth,
		&r.ipv4,
		&r.ipv6,
		&r.tcp,
		&r.udp,
		&r.payload,
	)
	r.decoded = make([]gopacket.LayerType, 0, 8)

	return r, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	data, _, err := h.handle.ReadPacketData()
	if err != nil {
		return nil, nil, err
	}
	h.decoded = h.decoded[:0]
	_ = h.parser.DecodeLayers(data, &h.decoded)
	if len(h.decoded) == 0 {
		return nil, nil, nil
	}

	addr := &net.UDPAddr{}
	for _, t := range h.decoded {
		switch t {
		case layers.LayerTypeIPv4:
			addr.IP = h.ipv4.SrcIP
		case layers.LayerTypeIPv6:
			addr.IP = h.ipv6.SrcIP
		case layers.LayerTypeTCP:
			addr.Port = int(h.tcp.SrcPort)
		case layers.LayerTypeUDP:
			addr.Port = int(h.udp.SrcPort)
		}
	}
	if addr.IP == nil || addr.Port == 0 || len(h.payload) == 0 {
		return nil, nil, nil
	}

	return h.payload, addr, nil
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
