package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/internal/syncstore"
	"goodkind.io/unifi-go/internal/unifiapi"
)

// informKeyLength is the character count of a UniFi inform key.
const informKeyLength = 32

// runImportController registers the inform key of every stored device, so a
// shadow controller can answer those devices once an operator promotes it. It
// sends no configuration and changes no device.
func runImportController(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("import-controller", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socket := flags.String("socket", "/tmp/unifi-go.sock", "local control socket")
	directory := flags.String("dir", "state/controller", "stored record directory")
	site := flags.String("site", "default", "controller site name")
	if err := flags.Parse(args); err != nil {
		return errors.New("invalid command arguments")
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected command arguments")
	}
	collection, found := unifiapi.Lookup("device")
	if !found {
		return errors.New("the device collection is missing from the registry")
	}
	store, err := syncstore.Open(*directory)
	if err != nil {
		return syncFailure("open record store", err)
	}
	records, err := store.Read(*site, collection)
	if err != nil {
		return syncFailure("read stored devices", err)
	}
	return importDeviceKeys(ctx, *socket, records, output)
}

func importDeviceKeys(ctx context.Context, socket string, records []unifiapi.Record, output io.Writer) error {
	imported, skipped := 0, []string{}
	for _, record := range records {
		mac, present := record.Text("mac")
		if !present || mac == "" {
			continue
		}
		key, keyPresent := record.Text("x_authkey")
		if !keyPresent || len(key) != informKeyLength {
			skipped = append(skipped, mac)
			continue
		}
		if err := importOneKey(ctx, socket, mac, key); err != nil {
			return err
		}
		imported++
	}
	slices.Sort(skipped)
	fmt.Fprintf(output, "imported %d device keys\n", imported)
	if len(skipped) > 0 {
		fmt.Fprintf(output, "skipped %d without a stored inform key: %s\n", len(skipped), strings.Join(skipped, " "))
	}
	return nil
}

// importOneKey hands the key to the controller through a mode-0600 file,
// because the control request carries secrets by file reference only.
func importOneKey(ctx context.Context, socket, mac, key string) error {
	file, err := os.CreateTemp("", "unifi-go-inform-key-")
	if err != nil {
		return syncFailure("create inform key file", err)
	}
	path := file.Name()
	defer func() {
		if removeErr := os.Remove(path); removeErr != nil {
			slog.Warn("inform key file remove failed", slog.String("error", removeErr.Error()))
		}
	}()
	if _, err := file.WriteString(key); err != nil {
		file.Close()
		return syncFailure("write inform key file", err)
	}
	if err := file.Close(); err != nil {
		return syncFailure("close inform key file", err)
	}
	slog.Info("import device key", slog.String("mac", mac))
	request := controller.ControlRequest{
		Operation: controller.OpImport, MAC: mac, KeyFile: filepath.Clean(path),
		Command: nil, Device: "", AP: nil, Switch: nil, Config: nil, TypedCommand: nil,
		Baseline: nil, SetupSSH: false, PreviewToken: "", WiFiAdd: nil, WiFiSet: nil,
		WiFiRemove: nil, Radio: nil, Port: nil,
	}
	if err := control(ctx, socket, request, io.Discard); err != nil {
		return err
	}
	return nil
}
