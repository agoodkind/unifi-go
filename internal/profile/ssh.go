package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/network"
)

// WriteSSH changes only supplied credentials, preserving service policy.
func WriteSSH(values configmap.Values, ssh network.SSHConfig, secrets SecretReader) error {
	if ssh.Username.Present {
		if strings.ContainsAny(ssh.Username.Value, "\r\n") {
			return &network.ControlError{Code: network.InvalidConfig, Field: "ssh.username"}
		}
		if err := values.Set("users.1.name", ssh.Username.Value); err != nil {
			return &network.ControlError{Code: network.InvalidConfig, Field: "ssh.username"}
		}
	}
	if !ssh.Password.Present {
		return nil
	}
	if secrets == nil {
		return &network.ControlError{Code: network.FileReadFailed, Field: "ssh.password"}
	}
	username := values["users.1.name"]
	if username == "" {
		return &network.ControlError{Code: network.PolicyRequired, Field: "ssh.username"}
	}
	password, err := secrets.ReadSecret(ssh.Password.Value)
	if err != nil {
		return &network.ControlError{Code: network.FileReadFailed, Field: "ssh.password"}
	}
	if len(password) == 0 || bytes.ContainsAny(password, "\r\n") {
		return &network.ControlError{Code: network.InvalidConfig, Field: "ssh.password"}
	}
	digest := sha256.Sum256(append(append([]byte(username), 0), password...))
	salt := "$6$" + hex.EncodeToString(digest[:8])
	hash, err := sha512_crypt.New().Generate(password, []byte(salt))
	if err != nil {
		return &network.ControlError{Code: network.EncodingFailed, Field: "ssh.password"}
	}
	if err := values.Set("users.1.password", hash); err != nil {
		slog.Warn("configuration composition failed")
		return fmt.Errorf("write SSH password: %w", err)
	}
	return nil
}
