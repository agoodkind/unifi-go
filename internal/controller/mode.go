package controller

import (
	"context"
	"errors"
	"log/slog"
)

// ModeName states whether this controller answers device informs.
type ModeName string

const (
	// ModeShadow reads and stores state while another controller owns the
	// devices. The control socket answers and the device listener stays unbound.
	ModeShadow ModeName = "shadow"
	// ModeAuthoritative answers device informs on the bound address.
	ModeAuthoritative ModeName = "authoritative"
)

// ModeReport names the current mode and, when authoritative, where devices
// reach this controller.
type ModeReport struct {
	Mode    ModeName `json:"mode"`
	Address string   `json:"inform_address,omitempty"`
}

// InformListener binds and releases the device-facing listener. A shadow
// controller holds one that is not bound, so it can take over device traffic
// without restarting and without holding the address in the meantime.
type InformListener interface {
	Bind(ctx context.Context) (string, error)
	Release(ctx context.Context) error
	Address() string
}

// SetInformListener attaches the listener this controller binds and releases.
// Call it before serving begins.
func (c *Controller) SetInformListener(listener InformListener) {
	c.listener = listener
}

// Mode reports whether this controller currently answers device informs.
func (c *Controller) Mode() ModeReport {
	if c.listener == nil || c.listener.Address() == "" {
		return ModeReport{Mode: ModeShadow, Address: ""}
	}
	return ModeReport{Mode: ModeAuthoritative, Address: c.listener.Address()}
}

// Promote binds the device listener, so devices pointed at this controller
// reach it. Another process holding the address fails the promotion and leaves
// this controller shadowed.
func (c *Controller) Promote(ctx context.Context) (ModeReport, error) {
	slog.Info("controller promote requested")
	if c.listener == nil {
		return ModeReport{Mode: ModeShadow, Address: ""}, errors.New("this controller has no device listener to bind")
	}
	address, err := c.listener.Bind(ctx)
	if err != nil {
		return ModeReport{Mode: ModeShadow, Address: ""}, fault("bind the inform listener", err)
	}
	slog.Info("controller authoritative", slog.String("inform_address", address))
	return ModeReport{Mode: ModeAuthoritative, Address: address}, nil
}

// Demote releases the device listener. Devices stop reaching this controller at
// once, and their stored keys and configuration survive.
func (c *Controller) Demote(ctx context.Context) (ModeReport, error) {
	slog.Info("controller demote requested")
	if c.listener == nil {
		return ModeReport{Mode: ModeShadow, Address: ""}, nil
	}
	if err := c.listener.Release(ctx); err != nil {
		return ModeReport{Mode: ModeAuthoritative, Address: c.listener.Address()}, fault("release the inform listener", err)
	}
	slog.Info("controller shadowed")
	return ModeReport{Mode: ModeShadow, Address: ""}, nil
}
