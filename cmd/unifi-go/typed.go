package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"goodkind.io/unifi-go/network"
)

type typedOperation string

const (
	operationApply   typedOperation = "apply"
	operationDevices typedOperation = "devices"
	operationDevice  typedOperation = "device"
	operationClients typedOperation = "clients"
	operationPorts   typedOperation = "ports"
)

func runTyped(ctx context.Context, args []string, output io.Writer) error {
	operation := typedOperation(args[0])
	remaining := args[1:]
	family := ""
	if operation == "apply" {
		if len(remaining) == 0 || (remaining[0] != "ap" && remaining[0] != "switch" && remaining[0] != "config") {
			return errors.New("apply requires ap, switch, or config")
		}
		family, remaining = remaining[0], remaining[1:]
	}
	if operation == operationApply && family == "config" {
		return runConfigApply(ctx, remaining, output)
	}
	flags := flag.NewFlagSet(string(operation), flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socket := flags.String("socket", "/tmp/unifi-go.sock", "local control socket")
	device := flags.String("device", "", "device identifier")
	file := flags.String("file", "", "typed configuration file")
	if err := flags.Parse(remaining); err != nil {
		return errors.New("invalid command arguments")
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected command arguments")
	}
	client := network.Dial(*socket)
	if operation == "devices" {
		devices, err := client.Devices(ctx)
		if err != nil {
			slog.Error("list devices failed", "err", err)
			return fmt.Errorf("list devices: %w", err)
		}
		return encodeTyped(output, devices)
	}
	if *device == "" {
		return errors.New("device is required")
	}
	id := network.DeviceID(*device)
	if operation == "apply" {
		return applyTyped(ctx, client, id, family, *file, output)
	}
	snapshot, err := client.Device(ctx, id)
	if err != nil {
		slog.Error("read device failed", "err", err)
		return fmt.Errorf("read device: %w", err)
	}
	switch operation {
	case operationClients:
		if snapshot.AP == nil {
			return errors.New("device is not an access point")
		}
		return encodeTyped(output, snapshot.AP.Clients)
	case operationPorts:
		if snapshot.Switch == nil {
			return errors.New("device is not a switch")
		}
		return encodeTyped(output, snapshot.Switch.Ports)
	case operationDevice:
		return encodeTyped(output, snapshot)
	case operationApply, operationDevices:
		return errors.New("invalid snapshot operation")
	default:
		return errors.New("unknown snapshot operation")
	}
}

func runConfigApply(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("apply config", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socket := flags.String("socket", "/tmp/unifi-go.sock", "local control socket")
	device := flags.String("device", "", "device identifier")
	version := flags.String("version", "", "configuration version")
	managementFile := flags.String("management-file", "", "management configuration file")
	systemFile := flags.String("system-file", "", "system configuration file")
	if err := flags.Parse(args); err != nil {
		return errors.New("invalid command arguments")
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected command arguments")
	}
	if *device == "" {
		return errors.New("device is required")
	}
	if *managementFile == "" && *systemFile == "" {
		return errors.New("apply config requires management-file or system-file")
	}
	management, err := readConfigFile(*managementFile)
	if err != nil {
		return err
	}
	system, err := readConfigFile(*systemFile)
	if err != nil {
		return err
	}
	client := network.Dial(*socket)
	queued, err := client.ApplyConfig(ctx, network.DeviceID(*device), network.Config{Version: network.ConfigVersion(*version), Management: management, System: system})
	if err != nil {
		slog.Error("apply configuration failed", "err", err)
		return fmt.Errorf("apply configuration: %w", err)
	}
	return encodeTyped(output, queuedVersion{Version: queued})
}

func readConfigFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", errors.New("cannot read configuration file")
	}
	return string(data), nil
}

func decodeConfigFile[T network.APConfig | network.SwitchConfig](path string, config *T) error {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return errors.New("cannot read configuration file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return errors.New("cannot inspect configuration file")
	}
	if info.Size() > 8388608 {
		return errors.New("configuration file exceeds 8 MiB")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 8388608))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(config); err != nil {
		return errors.New("invalid typed configuration or unknown field")
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return errors.New("configuration must contain one JSON value")
	}
	return nil
}

func applyTyped(ctx context.Context, client *network.Client, id network.DeviceID, family, path string, output io.Writer) error {
	var version network.ConfigVersion
	var err error
	if family == "ap" {
		var config network.APConfig
		if err := decodeConfigFile(path, &config); err != nil {
			return err
		}
		version, err = client.ApplyAP(ctx, id, config)
	} else {
		var config network.SwitchConfig
		if err := decodeConfigFile(path, &config); err != nil {
			return err
		}
		version, err = client.ApplySwitch(ctx, id, config)
	}
	if err != nil {
		slog.Error("apply configuration failed", "err", err)
		return fmt.Errorf("apply configuration: %w", err)
	}
	return encodeTyped(output, queuedVersion{Version: version})
}

type queuedVersion struct {
	Version network.ConfigVersion `json:"version"`
}

func encodeTyped[T network.DeviceSnapshot | []network.DeviceSnapshot | []network.ClientSnapshot | []network.PortSnapshot | queuedVersion](output io.Writer, value T) error {
	if err := json.NewEncoder(output).Encode(value); err != nil {
		return errors.New("cannot write response")
	}
	return nil
}
