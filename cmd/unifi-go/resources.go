package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"goodkind.io/unifi-go/network"
)

type resourceGroup string

const (
	resourceWiFi  resourceGroup = "wifi"
	resourceRadio resourceGroup = "radio"
	resourcePort  resourceGroup = "port"
)

type resourceOperation string

const (
	resourceList   resourceOperation = "list"
	resourceAdd    resourceOperation = "add"
	resourceSet    resourceOperation = "set"
	resourceRemove resourceOperation = "remove"
)

func runResource(ctx context.Context, args []string, output io.Writer) error {
	if len(args) < 2 {
		return errors.New("resource command requires an operation")
	}
	group, operation := resourceGroup(args[0]), resourceOperation(args[1])
	remaining := args[2:]
	switch group {
	case resourceWiFi:
		return runWiFiResource(ctx, operation, remaining, output)
	case resourceRadio:
		if operation != resourceSet {
			return errors.New("radio requires set")
		}
		return runRadioResource(ctx, remaining, output)
	case resourcePort:
		if operation != resourceSet {
			return errors.New("port requires set")
		}
		return runPortResource(ctx, remaining, output)
	default:
		return errors.New("unknown resource command")
	}
}

func runWiFiResource(ctx context.Context, operation resourceOperation, args []string, output io.Writer) error {
	switch operation {
	case resourceList:
		flags, socket, device := resourceFlags("wifi list")
		if err := parseResourceFlags(flags, args); err != nil {
			return err
		}
		client := network.Dial(*socket)
		id, err := resourceDevice(ctx, client, *device, network.FamilyAP)
		if err != nil {
			return err
		}
		networks, err := client.WiFiNetworks(ctx, id)
		if err != nil {
			slog.Error("list WiFi resources failed", "err", err)
			return fmt.Errorf("list WiFi resources: %w", err)
		}
		return encodeTyped(output, networks)
	case resourceAdd:
		return runWiFiAdd(ctx, args, output)
	case resourceSet:
		return runWiFiSet(ctx, args, output)
	case resourceRemove:
		return runWiFiRemove(ctx, args, output)
	default:
		return errors.New("wifi requires list, add, set, or remove")
	}
}

func runWiFiAdd(ctx context.Context, args []string, output io.Writer) error {
	flags, socket, device := resourceFlags("wifi add")
	name := flags.String("name", "", "WiFi name")
	nameFile := flags.String("name-file", "", "WiFi name file")
	passwordFile := flags.String("password-file", "", "controller-visible password file")
	copyFrom := flags.String("copy-from", "", "source WiFi name")
	copyFromFile := flags.String("copy-from-file", "", "source WiFi name file")
	if err := parseResourceFlags(flags, args); err != nil {
		return err
	}
	selectedName, err := resourceSelector(*name, *nameFile, resourceFlagSet(flags, "name"), resourceFlagSet(flags, "name-file"), "name")
	if err != nil {
		return err
	}
	selectedSource, err := resourceSelector(*copyFrom, *copyFromFile, resourceFlagSet(flags, "copy-from"), resourceFlagSet(flags, "copy-from-file"), "copy-from")
	if err != nil {
		return err
	}
	if *passwordFile == "" {
		return errors.New("password-file is required")
	}
	client := network.Dial(*socket)
	id, err := resourceDevice(ctx, client, *device, network.FamilyAP)
	if err != nil {
		return err
	}
	version, err := client.AddWiFi(ctx, id, network.AddWiFiRequest{Name: selectedName, Password: network.SecretFile(*passwordFile), CopyFrom: selectedSource}) // gitleaks:allow -- controller-visible file reference
	if err != nil {
		slog.Error("add WiFi resource failed", "err", err)
		return fmt.Errorf("add WiFi resource: %w", err)
	}
	return encodeTyped(output, queuedVersion{Version: version})
}

func runWiFiSet(ctx context.Context, args []string, output io.Writer) error {
	flags, socket, device := resourceFlags("wifi set")
	currentName := flags.String("current-name", "", "current WiFi name")
	currentNameFile := flags.String("current-name-file", "", "current WiFi name file")
	file := flags.String("file", "", "WiFi resource file")
	if err := parseResourceFlags(flags, args); err != nil {
		return err
	}
	selectedName, err := resourceSelector(*currentName, *currentNameFile, resourceFlagSet(flags, "current-name"), resourceFlagSet(flags, "current-name-file"), "current-name")
	if err != nil {
		return err
	}
	var config network.WiFiNetwork
	if err := decodeConfigFile(*file, &config); err != nil {
		return err
	}
	client := network.Dial(*socket)
	id, err := resourceDevice(ctx, client, *device, network.FamilyAP)
	if err != nil {
		return err
	}
	version, err := client.SetWiFi(ctx, id, network.SetWiFiRequest{CurrentName: selectedName, Network: config})
	if err != nil {
		slog.Error("set WiFi resource failed", "err", err)
		return fmt.Errorf("set WiFi resource: %w", err)
	}
	return encodeTyped(output, queuedVersion{Version: version})
}

func runWiFiRemove(ctx context.Context, args []string, output io.Writer) error {
	flags, socket, device := resourceFlags("wifi remove")
	name := flags.String("name", "", "WiFi name")
	nameFile := flags.String("name-file", "", "WiFi name file")
	if err := parseResourceFlags(flags, args); err != nil {
		return err
	}
	selectedName, err := resourceSelector(*name, *nameFile, resourceFlagSet(flags, "name"), resourceFlagSet(flags, "name-file"), "name")
	if err != nil {
		return err
	}
	client := network.Dial(*socket)
	id, err := resourceDevice(ctx, client, *device, network.FamilyAP)
	if err != nil {
		return err
	}
	version, err := client.RemoveWiFi(ctx, id, selectedName)
	if err != nil {
		slog.Error("remove WiFi resource failed", "err", err)
		return fmt.Errorf("remove WiFi resource: %w", err)
	}
	return encodeTyped(output, queuedVersion{Version: version})
}

func runRadioResource(ctx context.Context, args []string, output io.Writer) error {
	flags, socket, device := resourceFlags("radio set")
	file := flags.String("file", "", "radio resource file")
	if err := parseResourceFlags(flags, args); err != nil {
		return err
	}
	var config network.RadioConfig
	if err := decodeConfigFile(*file, &config); err != nil {
		return err
	}
	client := network.Dial(*socket)
	id, err := resourceDevice(ctx, client, *device, network.FamilyAP)
	if err != nil {
		return err
	}
	version, err := client.SetRadio(ctx, id, config)
	if err != nil {
		slog.Error("set radio resource failed", "err", err)
		return fmt.Errorf("set radio resource: %w", err)
	}
	return encodeTyped(output, queuedVersion{Version: version})
}

func runPortResource(ctx context.Context, args []string, output io.Writer) error {
	flags, socket, device := resourceFlags("port set")
	file := flags.String("file", "", "switch port resource file")
	if err := parseResourceFlags(flags, args); err != nil {
		return err
	}
	var config network.SwitchPortConfig
	if err := decodeConfigFile(*file, &config); err != nil {
		return err
	}
	client := network.Dial(*socket)
	id, err := resourceDevice(ctx, client, *device, network.FamilySwitch)
	if err != nil {
		return err
	}
	version, err := client.SetSwitchPort(ctx, id, config)
	if err != nil {
		slog.Error("set switch port resource failed", "err", err)
		return fmt.Errorf("set switch port resource: %w", err)
	}
	return encodeTyped(output, queuedVersion{Version: version})
}

func resourceFlags(name string) (*flag.FlagSet, *string, *string) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socket := flags.String("socket", "/tmp/unifi-go.sock", "local control socket")
	device := flags.String("device", "", "device identifier")
	return flags, socket, device
}

func parseResourceFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return errors.New("invalid command arguments")
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected command arguments")
	}
	return nil
}

func resourceFlagSet(flags *flag.FlagSet, name string) bool {
	present := false
	flags.Visit(func(value *flag.Flag) {
		if value.Name == name {
			present = true
		}
	})
	return present
}

func resourceSelector(literal, path string, literalSet, pathSet bool, name string) (string, error) {
	if literalSet == pathSet {
		return "", errors.New(name + " requires exactly one literal or file")
	}
	if literalSet {
		if literal == "" {
			return "", errors.New(name + " must not be empty")
		}
		return literal, nil
	}
	if path == "" {
		return "", errors.New(name + " file must not be empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("cannot read " + name + " file")
	}
	value := string(data)
	if trimmed, found := strings.CutSuffix(value, "\r\n"); found {
		value = trimmed
	} else if strings.HasSuffix(value, "\n") || strings.HasSuffix(value, "\r") {
		value = value[:len(value)-1]
	}
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", errors.New(name + " file must contain one line")
	}
	return value, nil
}

func resourceDevice(ctx context.Context, client *network.Client, selected string, family network.DeviceFamily) (network.DeviceID, error) {
	if selected != "" {
		return network.DeviceID(selected), nil
	}
	devices, err := client.Devices(ctx)
	if err != nil {
		slog.Error("list devices for resource selection failed", "err", err)
		return "", fmt.Errorf("list devices: %w", err)
	}
	var candidates []network.DeviceID
	for _, device := range devices {
		if device.Family == family {
			candidates = append(candidates, device.ID)
		}
	}
	if len(candidates) != 1 {
		return "", &network.ControlError{Code: network.AmbiguousDevice}
	}
	return candidates[0], nil
}
