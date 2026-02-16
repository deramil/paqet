//go:build !pcap

package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
)

type SendHandle struct{}

func NewSendHandle(cfg *conf.Network) (*SendHandle, error) {
	return nil, fmt.Errorf("pcap support is disabled at build time; rebuild with -tags pcap")
}

func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr) error {
	return fmt.Errorf("pcap support is disabled at build time")
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {}

func (h *SendHandle) Close() {}
