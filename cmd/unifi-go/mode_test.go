package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type modeReply struct {
	Mode    string `json:"mode"`
	Address string `json:"inform_address"`
}

// shortSocketDirectory returns a directory whose path fits the length a Unix
// socket address allows, which the default temporary directory exceeds.
func shortSocketDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "ug-mode-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	return directory
}

// startShadowController runs the real serve command and returns its socket once
// the control socket answers.
func startShadowController(t *testing.T, listen string) string {
	t.Helper()
	socketDirectory := shortSocketDirectory(t)
	socket := filepath.Join(socketDirectory, "control.sock")
	state := filepath.Join(t.TempDir(), "devices.json")
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() {
		stopped <- run(ctx, []string{
			"serve", "--mode", "shadow", "--listen", listen,
			"--advertise", "http://127.0.0.1:18080/inform",
			"--state", state, "--socket", socket,
		}, io.Discard)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); err == nil {
			return socket
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the control socket never appeared")
	return ""
}

func readMode(t *testing.T, socket, operation string) modeReply {
	t.Helper()
	output := new(bytes.Buffer)
	if err := run(t.Context(), []string{operation, "--socket", socket}, output); err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
	var reply modeReply
	if err := json.Unmarshal(output.Bytes(), &reply); err != nil {
		t.Fatalf("decode %s reply %q: %v", operation, output.String(), err)
	}
	return reply
}

func TestServe_ShadowAnswersControlWithoutBindingTheDeviceListener(t *testing.T) {
	socket := startShadowController(t, "127.0.0.1:0")

	reply := readMode(t, socket, "mode")

	if reply.Mode != "shadow" {
		t.Fatalf("mode is %q, want shadow", reply.Mode)
	}
	if reply.Address != "" {
		t.Fatalf("a shadow controller reports the address %q, want none", reply.Address)
	}
}

func TestServe_PromoteBindsTheDeviceListenerAndDemoteReleasesIt(t *testing.T) {
	socket := startShadowController(t, "127.0.0.1:0")

	promoted := readMode(t, socket, "promote")

	if promoted.Mode != "authoritative" || promoted.Address == "" {
		t.Fatalf("promote reported %+v, want an authoritative controller with an address", promoted)
	}
	response, err := http.Post("http://"+promoted.Address+"/inform", "application/octet-stream", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("the promoted controller refused a device inform: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Error(err)
	}
	if response.StatusCode == http.StatusNotFound {
		t.Fatal("the promoted controller does not serve the inform path")
	}

	demoted := readMode(t, socket, "demote")

	if demoted.Mode != "shadow" || demoted.Address != "" {
		t.Fatalf("demote reported %+v, want a shadow controller", demoted)
	}
	if _, err := net.DialTimeout("tcp", promoted.Address, time.Second); err == nil {
		t.Fatal("the released address still accepts connections")
	}
}

func TestServe_PromoteRefusesAnAddressAnotherControllerAnswers(t *testing.T) {
	listenerConfig := new(net.ListenConfig)
	occupied, err := listenerConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := occupied.Close(); err != nil {
			t.Error(err)
		}
	})
	socket := startShadowController(t, occupied.Addr().String())

	output := new(bytes.Buffer)
	promoteErr := run(t.Context(), []string{"promote", "--socket", socket}, output)

	if promoteErr == nil {
		t.Fatal("promote took an address another controller answers on")
	}
	if !strings.Contains(promoteErr.Error(), "another controller answers") {
		t.Fatalf("promote failed with %q, want it to name the occupied address", promoteErr)
	}
	if reply := readMode(t, socket, "mode"); reply.Mode != "shadow" {
		t.Fatalf("a refused promotion left the controller in %q, want shadow", reply.Mode)
	}
}
