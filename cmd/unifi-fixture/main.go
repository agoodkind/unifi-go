// Command unifi-fixture converts private UniFi traffic into synthetic fixtures.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"goodkind.io/unifi-go/internal/fixture"
)

func main() {
	capture := flag.String("capture", "", "source pcap")
	family := flag.String("family", "", "ap or switch")
	output := flag.String("output", "", "fixture output directory")
	keys := flag.String("keys", "", "optional newline-separated inform keys")
	provenance := flag.String("provenance", "", "verified run provenance JSON")
	flag.Parse()
	slog.Info("starting fixture generation", "family", *family)
	if err := fixture.Generate(fixture.Options{
		Capture:        *capture,
		Family:         *family,
		Output:         *output,
		KeyFile:        *keys,
		ProvenanceFile: *provenance,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
