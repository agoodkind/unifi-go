// Command unifi-go serves and controls a minimal UniFi inform controller.
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
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/internal/profile/ap"
	"goodkind.io/unifi-go/internal/profile/switches"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout)
	stop()
	if err != nil {
		slog.Error("unifi-go failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: unifi-go serve|adopt|import|send|status|apply|wifi|radio|port|sync [flags]")
	}
	if args[0] == "sync" {
		return runSync(ctx, args[1:], output)
	}
	if args[0] == "wifi" || args[0] == "radio" || args[0] == "port" {
		return runResource(ctx, args, output)
	}
	switch typedOperation(args[0]) {
	case operationApply, operationDevices, operationDevice, operationClients, operationPorts, operationCommand, operationBaselineImport:
		return runTyped(ctx, args, output)
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	socket := flags.String("socket", "/tmp/unifi-go.sock", "local control socket")
	listen := flags.String("listen", ":18080", "inform listener")
	advertise := flags.String("advertise", "", "AP-reachable http://IP:port/inform URL")
	state := flags.String("state", "state/devices.json", "device state file")
	mac := flags.String("mac", "", "device MAC")
	keyFile := flags.String("key-file", "", "inform key file")
	commandFile := flags.String("file", "", "controller JSON reply file")
	setupSSH := flags.Bool("setup-ssh", false, "install generated SSH credentials during adoption")
	if err := flags.Parse(args[1:]); err != nil {
		return failure("parse arguments", err)
	}
	if args[0] == "serve" {
		return serve(ctx, *listen, *advertise, *state, *socket, output)
	}
	request := controller.ControlRequest{Operation: controller.Operation(args[0]), MAC: *mac, KeyFile: *keyFile, Command: nil, Device: "", AP: nil, Switch: nil, Config: nil, TypedCommand: nil, Baseline: nil, SetupSSH: *setupSSH, PreviewToken: "", WiFiAdd: nil, WiFiSet: nil, WiFiRemove: nil, Radio: nil, Port: nil}
	if args[0] == "send" || args[0] == "adopt" {
		data, err := os.ReadFile(filepath.Clean(*commandFile))
		if err != nil {
			return failure("read command file", err)
		}
		var command controller.Reply
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&command); err != nil {
			return failure("decode typed command file", err)
		}
		request.Command = &command
	}
	return control(ctx, *socket, request, output)
}

func control(ctx context.Context, socket string, request controller.ControlRequest, output io.Writer) error {
	body, err := json.Marshal(request)
	if err != nil {
		return failure("encode control request", err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		connection, dialErr := (&net.Dialer{}).DialContext(ctx, "unix", socket)
		if dialErr != nil {
			return nil, failure("connect control socket", dialErr)
		}
		return connection, nil
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 45 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://local/control", bytes.NewReader(body))
	if err != nil {
		return failure("create control request", err)
	}
	response, err := client.Do(req)
	if err != nil {
		return failure("send control request", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		message, err := io.ReadAll(response.Body)
		if err != nil {
			return failure("read control error", err)
		}
		return fmt.Errorf("control request failed: %s", message)
	}
	_, err = io.Copy(output, response.Body)
	if err != nil {
		return failure("write control response", err)
	}
	return nil
}

// clearStaleSocket removes a control socket that no controller is listening on.
// An unclean exit leaves the file behind, and every later start then fails to
// bind. A socket that still accepts a connection belongs to a running
// controller and survives.
func clearStaleSocket(ctx context.Context, socket string) error {
	slog.Info("control socket check")
	info, err := os.Stat(socket)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat control socket: %w", err)
	}
	if info.Mode().Type() != os.ModeSocket {
		return errors.New("control socket path holds a regular file")
	}
	dialer := &net.Dialer{Timeout: time.Second}
	// #nosec G704 -- socket is the operator-supplied local control path, not a network address
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err == nil {
		conn.Close()
		return errors.New("another controller owns the control socket")
	}
	slog.Warn("removing stale control socket")
	if err := os.Remove(socket); err != nil {
		return fmt.Errorf("remove control socket: %w", err)
	}
	return nil
}

func serve(ctx context.Context, listen, advertise, stateFile, socket string, output io.Writer) error {
	c, err := controller.Open(stateFile, advertise, profile.NewRegistry(ap.New(), switches.New()))
	if err != nil {
		return failure("open controller", err)
	}
	socket = filepath.Clean(socket)
	if err := clearStaleSocket(ctx, socket); err != nil {
		return failure("clear stale control socket", err)
	}
	listenerConfig := new(net.ListenConfig)
	controlListener, err := listenerConfig.Listen(ctx, "unix", socket)
	if err != nil {
		return failure("listen on control socket", err)
	}
	defer controlListener.Close()
	if err := os.Chmod(socket, 0o600); err != nil {
		return failure("set control socket permissions", err)
	}
	informListener, err := listenerConfig.Listen(ctx, "tcp", listen)
	if err != nil {
		return failure("listen for informs", err)
	}
	defer informListener.Close()
	informServer := &http.Server{Handler: c, ReadHeaderTimeout: 10 * time.Second}
	controlServer := &http.Server{Handler: http.HandlerFunc(c.Control), ReadHeaderTimeout: 10 * time.Second}
	errorsChannel := make(chan error, 2)
	serveHTTP(informServer, informListener, errorsChannel)
	serveHTTP(controlServer, controlListener, errorsChannel)
	fmt.Fprintf(output, "inform=%s control=%s\n", informListener.Addr(), socket)
	select {
	case <-ctx.Done():
	case err = <-errorsChannel:
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if shutdownErr := informServer.Shutdown(shutdown); shutdownErr != nil {
		return failure("stop inform server", shutdownErr)
	}
	if shutdownErr := controlServer.Shutdown(shutdown); shutdownErr != nil {
		return failure("stop control server", shutdownErr)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func serveHTTP(server *http.Server, listener net.Listener, result chan<- error) {
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				err := fmt.Errorf("HTTP server panicked: %v", recovered)
				slog.Error("HTTP server panicked", "error", err)
				result <- err
			}
		}()
		result <- server.Serve(listener)
	}()
}

func failure(message string, err error) error {
	slog.Error(message, "error", err)
	return fmt.Errorf("%s: %w", message, err)
}
