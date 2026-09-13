package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/network"
)

type typedOperation string

const (
	operationApply          typedOperation = "apply"
	operationDevices        typedOperation = "devices"
	operationDevice         typedOperation = "device"
	operationClients        typedOperation = "clients"
	operationPorts          typedOperation = "ports"
	operationCommand        typedOperation = "command"
	operationBaselineImport typedOperation = "baseline-import"
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
	dryRun := flags.Bool("dry-run", false, "preview typed configuration without applying it")
	tokenFile := flags.String("preview-token-file", "", "opaque preview token file")
	if err := flags.Parse(remaining); err != nil {
		return errors.New("invalid command arguments")
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected command arguments")
	}
	if (*dryRun || *tokenFile != "") && operation != operationApply {
		return errors.New("preview flags require typed apply")
	}
	if *dryRun && *tokenFile != "" {
		return errors.New("dry-run cannot be combined with preview-token-file")
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
	if operation == operationCommand || operation == operationBaselineImport {
		return runTransportTyped(ctx, client, id, operation, *file)
	}
	if operation == "apply" {
		return applyTyped(ctx, client, id, family, *file, *dryRun, *tokenFile, output)
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
	case operationApply, operationDevices, operationCommand, operationBaselineImport:
		return errors.New("invalid snapshot operation")
	default:
		return errors.New("unknown snapshot operation")
	}
}

func runTransportTyped(ctx context.Context, client *network.Client, id network.DeviceID, operation typedOperation, path string) error {
	if operation == operationCommand {
		var command network.Command
		if err := decodeConfigFile(path, &command); err != nil {
			return err
		}
		if err := client.SendCommand(ctx, id, command); err != nil {
			slog.Error("send command failed", "err", err)
			return fmt.Errorf("send command: %w", err)
		}
		return nil
	}
	var baseline network.BaselineImport
	if err := decodeConfigFile(path, &baseline); err != nil {
		return err
	}
	if err := client.ImportBaseline(ctx, id, baseline); err != nil {
		slog.Error("import baseline failed", "err", err)
		return fmt.Errorf("import baseline: %w", err)
	}
	return nil
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

func decodeConfigFile[T network.APConfig | network.SwitchConfig | network.Command | network.BaselineImport | network.WiFiNetwork | network.RadioConfig | network.SwitchPortConfig](path string, config *T) error {
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
	body, err := io.ReadAll(io.LimitReader(file, 8388609))
	if err != nil {
		return errors.New("cannot read configuration file")
	}
	if len(body) > 8388608 {
		return errors.New("configuration file exceeds 8 MiB")
	}
	if !controller.ValidConfigEnvelopeEncoding(body) {
		return &network.ControlError{Code: network.InvalidEncoding}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(config); err != nil {
		return errors.New("invalid typed configuration or unknown field")
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return errors.New("configuration must contain one JSON value")
	}
	return nil
}

func applyTyped(ctx context.Context, client *network.Client, id network.DeviceID, family, path string, dryRun bool, tokenFile string, output io.Writer) error {
	if dryRun {
		return previewTyped(ctx, client, id, family, path, output)
	}
	var version network.ConfigVersion
	var err error
	var token network.PreviewToken
	if tokenFile != "" {
		data, readErr := os.ReadFile(filepath.Clean(tokenFile))
		if readErr != nil {
			return errors.New("cannot read preview token file")
		}
		token = network.PreviewToken(strings.TrimSpace(string(data)))
		if token == "" {
			return &network.ControlError{Code: network.PreviewStale}
		}
	}
	switch family {
	case "ap":
		var config network.APConfig
		if err := decodeConfigFile(path, &config); err != nil {
			return err
		}
		if token != "" {
			version, err = client.ApplyAPPreview(ctx, id, config, token)
		} else {
			version, err = client.ApplyAP(ctx, id, config)
		}
	default:
		var config network.SwitchConfig
		if err := decodeConfigFile(path, &config); err != nil {
			return err
		}
		if token != "" {
			version, err = client.ApplySwitchPreview(ctx, id, config, token)
		} else {
			version, err = client.ApplySwitch(ctx, id, config)
		}
	}
	if err != nil {
		slog.Error("apply configuration failed", "err", err)
		return fmt.Errorf("apply configuration: %w", err)
	}
	return encodeTyped(output, queuedVersion{Version: version})
}

func previewTyped(ctx context.Context, client *network.Client, id network.DeviceID, family, path string, output io.Writer) error {
	var preview network.ConfigPreview
	var err error
	if family == "ap" {
		var config network.APConfig
		if err := decodeConfigFile(path, &config); err != nil {
			return err
		}
		preview, err = client.PreviewAP(ctx, id, config)
	} else {
		var config network.SwitchConfig
		if err := decodeConfigFile(path, &config); err != nil {
			return err
		}
		preview, err = client.PreviewSwitch(ctx, id, config)
	}
	if err != nil {
		slog.Error("preview configuration failed", "err", err)
		return fmt.Errorf("preview configuration: %w", err)
	}
	return encodeTyped(output, preview)
}

type queuedVersion struct {
	Version network.ConfigVersion `json:"version"`
}

func encodeTyped[T network.DeviceSnapshot | []network.DeviceSnapshot | []network.ClientSnapshot | []network.PortSnapshot | []network.WiFiNetworkView | network.ConfigPreview | queuedVersion](output io.Writer, value T) error {
	if err := json.NewEncoder(output).Encode(value); err != nil {
		return errors.New("cannot write response")
	}
	return nil
}
