// Package unifiapi reads and writes the configuration records a UniFi Network
// Application holds, as generic JSON records rather than one typed subject.
package unifiapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

const (
	requestTimeout   = 45 * time.Second
	responseMaxBytes = 32 << 20
	csrfHeader       = "X-Csrf-Token"
)

// Record is one controller record with its fields left as received.
type Record map[string]json.RawMessage

// Clone returns an independent copy of the record.
func (record Record) Clone() Record {
	return maps.Clone(record)
}

// Text returns one field decoded as a JSON string.
func (record Record) Text(field string) (string, bool) {
	raw, present := record[field]
	if !present {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

// Config selects the controller, its site, and the operator account.
type Config struct {
	BaseURL  string
	Site     string
	Username string
	Password string
	Insecure bool
}

// Client calls one site on one UniFi Network Application.
type Client struct {
	http *http.Client
	base *url.URL
	site string
	csrf string
}

type envelope struct {
	Meta envelopeMeta      `json:"meta"`
	Data []json.RawMessage `json:"data"`
}

type envelopeMeta struct {
	RC      string `json:"rc"`
	Message string `json:"msg"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Dial signs in to the controller and returns a client holding that session.
func Dial(ctx context.Context, config Config) (*Client, error) {
	slog.Info("unifi controller login", slog.String("url", config.BaseURL), slog.String("site", config.Site))
	base, err := url.Parse(config.BaseURL)
	if err != nil {
		return nil, failure("parse controller url", err)
	}
	if base.Scheme != "https" && base.Scheme != "http" {
		return nil, errors.New("controller url requires an http or https scheme")
	}
	if config.Site == "" {
		return nil, errors.New("controller site is required")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, failure("create cookie jar", err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.Insecure {
		// #nosec G402 -- a self-hosted controller presents its own certificate and the operator opts in by flag
		tlsConfig.InsecureSkipVerify = true
	}
	client := &Client{
		http: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Jar: jar, Timeout: requestTimeout},
		base: base,
		site: config.Site,
		csrf: "",
	}
	if err := client.login(ctx, config.Username, config.Password); err != nil {
		return nil, err
	}
	return client, nil
}

// Close releases the idle connections this session opened.
func (client *Client) Close() {
	slog.Info("unifi controller session close", slog.String("site", client.site))
	client.http.CloseIdleConnections()
}

// Site returns the site this client reads and writes.
func (client *Client) Site() string { return client.site }

// List returns every record in one collection.
func (client *Client) List(ctx context.Context, collection Collection) ([]Record, error) {
	slog.Info("unifi controller list", slog.String("collection", string(collection.Name)), slog.String("site", client.site))
	data, err := client.call(ctx, http.MethodGet, client.sitePath(collection.ListPath), nil)
	if err != nil {
		return nil, err
	}
	records := make([]Record, 0, len(data))
	for _, raw := range data {
		var record Record
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, failure("decode "+string(collection.Name)+" record", err)
		}
		records = append(records, record)
	}
	return records, nil
}

// Create adds one record and returns the record the controller stored.
func (client *Client) Create(ctx context.Context, collection Collection, record Record) (Record, error) {
	slog.Info("unifi controller create", slog.String("collection", string(collection.Name)))
	if !collection.Creatable {
		return nil, fmt.Errorf("collection %s does not accept new records", collection.Name)
	}
	return client.write(ctx, http.MethodPost, client.sitePath(collection.CreatePath()), collection, record)
}

// Update replaces one record and returns the record the controller stored.
func (client *Client) Update(ctx context.Context, collection Collection, identity, id string, record Record) (Record, error) {
	slog.Info("unifi controller update", slog.String("collection", string(collection.Name)), slog.String("identity", identity))
	if !collection.Writable {
		return nil, fmt.Errorf("collection %s is read only", collection.Name)
	}
	if id == "" {
		return nil, fmt.Errorf("collection %s update needs a record identifier", collection.Name)
	}
	return client.write(ctx, http.MethodPut, client.sitePath(collection.RecordPath(identity, id)), collection, record)
}

// Delete removes one record.
func (client *Client) Delete(ctx context.Context, collection Collection, identity, id string) error {
	slog.Info("unifi controller delete", slog.String("collection", string(collection.Name)), slog.String("identity", identity))
	if !collection.Deletable {
		return fmt.Errorf("collection %s does not accept record removal", collection.Name)
	}
	if id == "" {
		return fmt.Errorf("collection %s removal needs a record identifier", collection.Name)
	}
	_, err := client.call(ctx, http.MethodDelete, client.sitePath(collection.RecordPath(identity, id)), nil)
	return err
}

func (client *Client) write(ctx context.Context, method, path string, collection Collection, record Record) (Record, error) {
	body, err := json.Marshal(record)
	if err != nil {
		return nil, failure("encode "+string(collection.Name)+" record", err)
	}
	data, err := client.call(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return Record{}, nil
	}
	var stored Record
	if err := json.Unmarshal(data[0], &stored); err != nil {
		return nil, failure("decode stored "+string(collection.Name)+" record", err)
	}
	return stored, nil
}

func (client *Client) login(ctx context.Context, username, password string) error {
	if username == "" || password == "" {
		return errors.New("controller username and password are required")
	}
	// #nosec G117 -- the controller login endpoint takes the operator password in the request body
	body, err := json.Marshal(loginRequest{Username: username, Password: password})
	if err != nil {
		return failure("encode login request", err)
	}
	response, err := client.send(ctx, http.MethodPost, "/api/login", body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if token := response.Header.Get(csrfHeader); token != "" {
		client.csrf = token
	}
	_, err = decodeEnvelope(response)
	return err
}

func (client *Client) sitePath(suffix string) string {
	return "/api/s/" + url.PathEscape(client.site) + "/" + strings.TrimPrefix(suffix, "/")
}

func (client *Client) call(ctx context.Context, method, path string, body []byte) ([]json.RawMessage, error) {
	response, err := client.send(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return decodeEnvelope(response)
}

func (client *Client) send(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	target := client.base.JoinPath(path)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return nil, failure("create controller request", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if client.csrf != "" {
		request.Header.Set(csrfHeader, client.csrf)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, failure("call controller "+path, err)
	}
	return response, nil
}

func decodeEnvelope(response *http.Response) ([]json.RawMessage, error) {
	var decoded envelope
	if err := json.NewDecoder(io.LimitReader(response.Body, responseMaxBytes)).Decode(&decoded); err != nil {
		return nil, failure("decode controller response", err)
	}
	if decoded.Meta.RC != "ok" {
		message := decoded.Meta.Message
		if message == "" {
			message = response.Status
		}
		slog.Error("controller rejected the request", slog.String("status", response.Status), slog.String("error", message))
		return nil, fmt.Errorf("controller rejected the request: %s", message)
	}
	return decoded.Data, nil
}

func failure(message string, err error) error {
	slog.Error(message, slog.String("error", err.Error()))
	return fmt.Errorf("%s: %w", message, err)
}
