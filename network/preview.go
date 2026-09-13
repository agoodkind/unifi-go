package network

import "context"

// PreviewToken identifies a private, expiring controller preview.
type PreviewToken string

// ConfigPreview counts record changes without exposing configuration values.
type ConfigPreview struct {
	Token   PreviewToken `json:"token"`
	Added   uint32       `json:"added"`
	Changed uint32       `json:"changed"`
	Removed uint32       `json:"removed"`
}

// PreviewAP compiles access point policy without persisting or queueing it.
func (client *Client) PreviewAP(ctx context.Context, id DeviceID, config APConfig) (ConfigPreview, error) {
	return client.preview(ctx, controlRequest{Operation: "preview-ap", Device: id, AP: &config})
}

// PreviewSwitch compiles switch policy without persisting or queueing it.
func (client *Client) PreviewSwitch(ctx context.Context, id DeviceID, config SwitchConfig) (ConfigPreview, error) {
	return client.preview(ctx, controlRequest{Operation: "preview-switch", Device: id, Switch: &config})
}

// ApplyAPPreview applies access point policy only when its preview still matches.
func (client *Client) ApplyAPPreview(ctx context.Context, id DeviceID, config APConfig, token PreviewToken) (ConfigVersion, error) {
	if token == "" {
		return "", &ControlError{Code: PreviewStale}
	}
	response, err := client.call(ctx, controlRequest{Operation: "apply-ap", Device: id, AP: &config, PreviewToken: token})
	return response.Version, err
}

// ApplySwitchPreview applies switch policy only when its preview still matches.
func (client *Client) ApplySwitchPreview(ctx context.Context, id DeviceID, config SwitchConfig, token PreviewToken) (ConfigVersion, error) {
	if token == "" {
		return "", &ControlError{Code: PreviewStale}
	}
	response, err := client.call(ctx, controlRequest{Operation: "apply-switch", Device: id, Switch: &config, PreviewToken: token})
	return response.Version, err
}

func (client *Client) preview(ctx context.Context, request controlRequest) (ConfigPreview, error) {
	response, err := client.call(ctx, request)
	if err != nil {
		return ConfigPreview{}, err
	}
	if response.Preview == nil {
		return ConfigPreview{}, &ControlError{Code: RequestFailed}
	}
	return *response.Preview, nil
}
