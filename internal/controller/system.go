package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

const controllerProtocolVersion = "0.1.0"

func (c *Controller) augmentSystem(values configmap.Values, device Device, descriptor profile.DeviceDescriptor) error {
	advertise, err := url.Parse(c.advertise)
	if err != nil || advertise.Hostname() == "" {
		return errors.New("invalid controller address")
	}
	controllerID := stableUUID(c.advertise, "controller")
	siteDigest := sha256.Sum256([]byte(c.advertise + "\x00site"))
	metadata := configmap.Values{
		"unifi.anonymous_controller_id":        controllerID,
		"unifi.anonymous_site_id":              stableUUID(c.advertise, "site"),
		"unifi.reporterid":                     controllerID,
		"unifi.siteid":                         hex.EncodeToString(siteDigest[:12]),
		"unifi.key":                            device.Key,
		"unifi.mcip":                           advertise.Hostname(),
		"unifi.version":                        controllerProtocolVersion,
		"unifi.cfgcap_info":                    "0x7",
		"unifi.feature.always_send_crash_logs": "disabled",
		"unifi.idp":                            "enabled",
	}
	for key, value := range metadata {
		if err := values.Set(key, value); err != nil {
			slog.Error("controller metadata encoding failed", "err", err)
			return fmt.Errorf("set controller metadata: %w", err)
		}
	}
	return preserveSSH(values, device, descriptor)
}

func stableUUID(identity, label string) string {
	digest := sha256.Sum256([]byte(identity + "\x00" + label))
	// Version 8 identifies a custom deterministic UUID derivation.
	digest[6] = (digest[6] & 0x0f) | 0x80
	digest[8] = (digest[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", digest[:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func preserveSSH(values configmap.Values, device Device, descriptor profile.DeviceDescriptor) error {
	for key := range values {
		if strings.HasPrefix(key, "sshd.") || strings.HasPrefix(key, "users.") {
			return nil
		}
	}
	if device.SSHUsername == "" || device.SSHPasswordHash == "" {
		return nil
	}
	ssh := configmap.Values{
		"sshd.status": "enabled", "sshd.1.status": "enabled", "sshd.auth.passwd": "enabled",
		"users.status": "enabled", "users.1.status": "enabled", "users.1.name": device.SSHUsername,
		"users.1.password": device.SSHPasswordHash,
	}
	if interfaceName := sshInterface(descriptor); interfaceName != "" {
		if err := ssh.Set("sshd.1.ifname", interfaceName); err != nil {
			slog.Error("SSH interface encoding failed", "err", err)
			return fmt.Errorf("set SSH interface: %w", err)
		}
	}
	for key, value := range ssh {
		if err := values.Set(key, value); err != nil {
			slog.Error("stored SSH configuration encoding failed", "err", err)
			return fmt.Errorf("preserve SSH configuration: %w", err)
		}
	}
	return nil
}

func sshInterface(descriptor profile.DeviceDescriptor) string {
	if descriptor.Family == network.FamilyAP {
		return "br0"
	}
	var selected profile.PortCapability
	for _, port := range descriptor.Ports {
		if port.Interface != "" && (selected.Interface == "" || port.Index < selected.Index) {
			selected = port
		}
	}
	return selected.Interface
}
