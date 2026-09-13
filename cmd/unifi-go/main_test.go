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
	"testing"

	"goodkind.io/unifi-go/internal/controller"
)

func TestCLIImportsQueuesAndReadsStatusThroughSocket(t *testing.T) {
	directory := t.TempDir()
	socketDirectory, err := os.MkdirTemp("/tmp", "ug-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(socketDirectory); err != nil {
			t.Error(err)
		}
	})
	socket := filepath.Join(socketDirectory, "control.sock")
	state := filepath.Join(directory, "devices.json")
	keyFile := filepath.Join(directory, "key")
	commandFile := filepath.Join(directory, "command.json")
	const mac = "02:00:00:00:00:01"
	if err := os.WriteFile(keyFile, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(commandFile, []byte(`{"_type":"setparam","cfgversion":"test","mgmt_cfg":"cfgversion=test\n"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	instance, err := controller.Open(state, "http://192.0.2.1:18080/inform")
	if err != nil {
		t.Fatal(err)
	}
	listenerConfig := new(net.ListenConfig)
	listener, err := listenerConfig.Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(instance.Control)}
	result := make(chan error, 1)
	go serveHTTP(server, listener, result)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		<-result
	})
	for _, args := range [][]string{
		{"import", "--socket", socket, "--mac", mac, "--key-file", keyFile},
		{"send", "--socket", socket, "--mac", mac, "--file", commandFile},
	} {
		if err := run(t.Context(), args, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := run(t.Context(), []string{"status", "--socket", socket}, &output); err != nil {
		t.Fatal(err)
	}
	var status []controller.Status
	if err := json.Unmarshal(output.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if len(status) != 1 || status[0].MAC != mac || status[0].Pending != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
	if bytes.Contains(output.Bytes(), []byte("0123456789abcdef0123456789abcdef")) {
		t.Fatal("status exposed the inform key")
	}
	reloaded, err := controller.Open(state, "http://192.0.2.1:18080/inform")
	if err != nil {
		t.Fatal(err)
	}
	if status := reloaded.Status(); len(status) != 1 || status[0].MAC != mac || status[0].Pending != 0 {
		t.Fatalf("unexpected reloaded state: %+v", status)
	}
}

func TestCLIMissingArguments(t *testing.T) {
	if err := run(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("missing command succeeded")
	}
}

func TestCLIRejectsUnknownCommandFields(t *testing.T) {
	commandFile := filepath.Join(t.TempDir(), "command.json")
	if err := os.WriteFile(commandFile, []byte(`{"_type":"noop","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(t.Context(), []string{"send", "--mac", "02:00:00:00:00:01", "--file", commandFile}, io.Discard)
	if err == nil {
		t.Fatal("unknown command field was accepted")
	}
}
