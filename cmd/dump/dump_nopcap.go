//go:build !pcap

package dump

import (
	"errors"

	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "dump",
	Short: "A raw packet dumper that logs TCP payloads for a given port.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return errors.New("dump command requires pcap support; rebuild with -tags pcap")
	},
}
