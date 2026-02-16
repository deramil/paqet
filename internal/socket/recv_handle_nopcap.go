//go:build !pcap

package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
)

type RecvHandle struct{}

func NewRecvHandle(cfg *conf.Network) (*RecvHandle, error) {
	return nil, fmt.Errorf("pcap support is disabled at build time; rebuild with -tags pcap")
}

func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	return nil, nil, fmt.Errorf("pcap support is disabled at build time")
}

func (h *RecvHandle) Close() {}
