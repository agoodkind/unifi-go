package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	informShutdownWait = 5 * time.Second
	occupiedProbeWait  = 2 * time.Second
)

// informBinder owns the device-facing listener and binds or releases it while
// the control socket keeps answering. A shadow controller starts with nothing
// bound, so another controller keeps the address until an operator promotes.
type informBinder struct {
	address  string
	handler  http.Handler
	failures chan<- error
	mu       sync.Mutex
	server   *http.Server
	listener net.Listener
}

func newInformBinder(address string, handler http.Handler, failures chan<- error) *informBinder {
	return &informBinder{
		address:  address,
		handler:  handler,
		failures: failures,
		mu:       sync.Mutex{},
		server:   nil,
		listener: nil,
	}
}

// Bind starts answering device informs and returns the bound address. Binding
// twice returns the address already bound.
func (binder *informBinder) Bind(ctx context.Context) (string, error) {
	binder.mu.Lock()
	defer binder.mu.Unlock()
	if binder.listener != nil {
		return binder.listener.Addr().String(), nil
	}
	if err := binder.refuseOccupied(ctx); err != nil {
		return "", err
	}
	listenerConfig := new(net.ListenConfig)
	listener, err := listenerConfig.Listen(ctx, "tcp", binder.address)
	if err != nil {
		return "", failure("listen for informs", err)
	}
	server := &http.Server{Handler: binder.handler, ReadHeaderTimeout: 10 * time.Second}
	binder.listener, binder.server = listener, server
	binder.serve(server, listener)
	slog.Info("inform listener bound", slog.String("address", listener.Addr().String()))
	return listener.Addr().String(), nil
}

// Release stops answering device informs. Releasing what is not bound succeeds.
func (binder *informBinder) Release(ctx context.Context) error {
	binder.mu.Lock()
	defer binder.mu.Unlock()
	if binder.server == nil {
		return nil
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), informShutdownWait)
	defer cancel()
	server := binder.server
	binder.server, binder.listener = nil, nil
	if err := server.Shutdown(shutdown); err != nil {
		return failure("stop inform server", err)
	}
	slog.Info("inform listener released")
	return nil
}

// Address returns the bound address, or the empty string while nothing is bound.
func (binder *informBinder) Address() string {
	binder.mu.Lock()
	defer binder.mu.Unlock()
	if binder.listener == nil {
		return ""
	}
	return binder.listener.Addr().String()
}

// serve runs one bound listener. A release closes the server on purpose, so
// that one error never ends the process.
func (binder *informBinder) serve(server *http.Server, listener net.Listener) {
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				err := fmt.Errorf("inform server panicked: %v", recovered)
				slog.Error("inform server panicked", slog.String("error", err.Error()))
				binder.failures <- err
			}
		}()
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("inform server stopped", slog.String("error", err.Error()))
			binder.failures <- err
		}
	}()
}

// refuseOccupied stops a promotion while another controller answers on the
// address. Binding alone does not catch this: the listener asks for address
// reuse, so a specific address binds next to a wildcard listener that a
// container published, and both then compete for device informs.
func (binder *informBinder) refuseOccupied(ctx context.Context) error {
	target := probeTarget(binder.address)
	if !addressAnswers(ctx, target) {
		slog.Info("inform address is free", slog.String("address", target))
		return nil
	}
	err := fmt.Errorf("another controller answers on %s; stop it before promoting", target)
	slog.Error("inform address already answers", slog.String("address", target), slog.String("error", err.Error()))
	return err
}

// addressAnswers reports whether a server accepts a connection on this address.
func addressAnswers(ctx context.Context, target string) bool {
	dialer := &net.Dialer{Timeout: occupiedProbeWait}
	connection, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return false
	}
	if closeErr := connection.Close(); closeErr != nil {
		slog.Warn("close occupancy probe failed", slog.String("error", closeErr.Error()))
	}
	return true
}

// probeTarget names an address to connect to. A listener address with no host,
// or one naming every address, is probed through the loopback interface.
func probeTarget(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return net.JoinHostPort(host, port)
}
