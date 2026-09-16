# Run unifi-go

Use unifi-go to adopt and configure access points and switches through encrypted
informs. It complements [unifi-emu](https://github.com/jamesbraid/unifi-emu), which
simulates devices and supplies the reused protocol library.

## Start the controller

Install Docker, Go matching the module version, and Make. Install TShark, mergecap,
and patch before running capture acceptance.

Set an IPv4 address reachable from the devices, then start the controller:

```sh
make check
export INFORM_IPV4_BIND='<host IPv4 address>'
export INFORM_URL='http://<host IPv4 address>:8080/inform'
docker compose up --build -d
docker compose exec inform /unifi-go status --socket=/runtime/control.sock
```

## Adopt a new device

Point the device at the inform URL through its local interface, discovery, or DHCP.
Set its MAC address and queue initial adoption:

```sh
DEVICE_MAC='<device MAC address>'
docker compose exec inform /unifi-go adopt \
    --socket=/runtime/control.sock --mac="$DEVICE_MAC" \
    --file=/examples/minimal-setparam.json
```

The controller sends `set-adopt` to a default-key device. After the device informs
with the assigned key, the controller sends the supplied initial configuration.
Supply SSH policy explicitly if the device needs SSH access.

Confirm a recent inform before applying a family configuration:

```sh
docker compose exec inform /unifi-go status --socket=/runtime/control.sock
```

## Import an adopted device

Importing registers an existing inform key. It does not reset the device or discover
its key. Put the key in a mode-0600 file in the mounted state directory, then run:

```sh
docker compose exec inform /unifi-go import \
    --socket=/runtime/control.sock --mac="$DEVICE_MAC" \
    --key-file=/state/inform-key
```

Point the device at this controller and wait for its report.

## Import a configuration baseline

For a missing or unusable typed baseline, import complete management and system
bodies from an operator-selected configuration. Include the corresponding typed
identities in `ap` or `switch`. Store the JSON envelope in a mode-0600 file:

```json
{
  "config": {
    "version": "operator-baseline",
    "management": "complete management configuration text",
    "system": "complete system configuration text"
  },
  "ap": {
    "networks": [{"name": "Lab", "bands": ["2.4ghz", "5ghz"]}]
  }
}
```

Replace the example bodies with complete configuration text and the identities with
the selected device's existing resources. For switches, supply `switch.ports` with
their physical `index` values instead of `ap`.

```sh
docker compose exec inform /unifi-go baseline-import \
    --socket=/runtime/control.sock --device="$DEVICE_MAC" --file=/state/baseline.json
```

Import sends no configuration. Omitted policy preserves the baseline value or its
absence. A supplied resource collection replaces its typed membership, so retain
every existing member that should survive. Peers may supply only their identities.
An omitted collection preserves every member; an empty collection removes its typed
members. Unknown records survive unless their owning resource is removed.
New networks and ports require explicit policy; missing required fields are rejected.

## Add or change one WiFi network

Use the resource commands for ordinary WiFi changes. First list the non-secret
desired networks:

```sh
docker compose exec inform /unifi-go wifi list \
    --socket=/runtime/control.sock --device="$DEVICE_MAC"
```

Create owner-only, one-line name files and an owner-only password file in the mounted
state directory. Copy one existing network's complete policy, change only its name
and password, and omit `--device` only when exactly one access point is eligible:

```sh
docker compose exec inform /unifi-go wifi add \
    --socket=/runtime/control.sock \
    --name-file=/state/new-wifi-name \
    --password-file=/state/new-wifi-password \
    --copy-from-file=/state/source-wifi-name
```

To disable Basic Service Set (BSS) Transition for one legacy network, save a WiFi
resource with the same name and `"bss_transition":"disabled"`. Apply it without
changing peer networks:

```sh
docker compose exec inform /unifi-go wifi set \
    --socket=/runtime/control.sock --device="$DEVICE_MAC" \
    --current-name-file=/state/legacy-wifi-name --file=/state/legacy-wifi.json
```

Use one active controller for each device. A resource change stops while another
configuration is pending or when the reported version has drifted. Select controller
ownership and run a deliberate full Apply to reconcile drift. Resource list output
omits secrets.

## Reconcile an access point

Create a private configuration file in the mounted state directory. Store the WiFi
password separately without a trailing newline and restrict both files to mode 0600.
Secret paths refer to files visible inside the controller container.

Use this configuration for one WPA2 network on virtual LAN (VLAN) 20 and two radios:

```json
{
  "country_code": 840,
  "networks": [{
    "name": "Lab",
    "enabled": true,
    "vlan": 20,
    "bands": ["2.4ghz", "5ghz"],
    "bss_transition": "disabled",
    "security": {"mode": "wpa2-personal", "psk": "/state/wifi-secret"}
  }],
  "radios": [
    {
      "band": "2.4ghz", "enabled": true, "channel": 6, "width_mhz": 20,
      "power": {"mode": "explicit", "dbm": 10}
    },
    {
      "band": "5ghz", "enabled": true, "channel": 44, "width_mhz": 40,
      "power": {"mode": "explicit", "dbm": 12}
    }
  ]
}
```

Choose the country, channels, widths, and power for the device and deployment.
Explicit channels and widths require capability evidence. Explicit power requires
reported minimum and maximum bounds. Set `channel` to null to select automatically;
omitting it preserves the baseline. Set `vlan` to null for untagged operation.
Other fields reject null, including legacy `ssh: null`; omit them to preserve policy.
Save the configuration in the mounted state directory under the filename used below:

```sh
docker compose exec inform /unifi-go apply ap \
    --socket=/runtime/control.sock --device="$DEVICE_MAC" --file=/state/ap.json
```

The returned version identifies the compiled configuration. Apply queues nothing
when the device already reports that version. Wait for a matching reported version
and inspect the applied device setting before claiming hardware acceptance.
An explicit `ssh` object changes only its supplied credential fields; omitted fields
preserve existing credentials.

## Preview a typed change

Preview with the same request file that will be applied. Keep the returned opaque
token private. The response contains record counts without configuration values;
the counts include connection and version metadata:

```sh
umask 077
docker compose exec inform /unifi-go apply ap \
    --socket=/runtime/control.sock --device="$DEVICE_MAC" \
    --file=/state/ap.json --dry-run > state/preview.json
```

Save only the response's `token` string into a mode-0600 token file in the mounted
state directory. Apply the unchanged request with that token:

```sh
docker compose exec inform /unifi-go apply ap \
    --socket=/runtime/control.sock --device="$DEVICE_MAC" \
    --file=/state/ap.json --preview-token-file=/state/preview-token
```

Use `apply switch` for switch previews. Preview does not write state or queue a
command. If the token expires or the baseline, capabilities, request, or resolved
secret contents change, preview again before applying.

## Apply complete configuration

Apply complete management or system configuration when the supplied records already
match the device. The controller sends supplied UTF-8 file contents unchanged and
does not infer the device family or validate configuration keys. Supply a version and
at least one configuration file:

```sh
docker compose exec inform /unifi-go apply config \
    --socket=/runtime/control.sock --device="$DEVICE_MAC" --version='config-v1' \
    --management-file=/state/mgmt.cfg --system-file=/state/system.cfg
```

Raw Apply replaces the baseline and invalidates typed ownership. Import complete
bodies and their explicit resource identities again before the next typed change.
After device drift, deliberately reconcile the supplied typed policy against the
chosen baseline through full Apply. Reports do not reconstruct missing configuration.

## Configure a switch

Choose port indexes and Power over Ethernet (PoE) modes from the reported inventory.
VLAN configuration requires explicit reported VLAN capability.
Use this configuration for an untagged access port on VLAN 20 and an uplink carrying
VLAN 20 tagged:

```json
{
  "ports": [
    {"index": 1, "enabled": true, "native_vlan": 20, "tagged_vlans": [], "poe": "off"},
    {"index": 8, "enabled": true, "native_vlan": 1, "tagged_vlans": [20]}
  ]
}
```

Save the configuration in the mounted state directory under the filename used below:

```sh
docker compose exec inform /unifi-go apply switch \
    --socket=/runtime/control.sock --device="$DEVICE_MAC" --file=/state/switch.json
```

## Inspect reports and restart

Read device reports and family observations:

```sh
AP_MAC='<access point MAC address>'
SWITCH_MAC='<switch MAC address>'
docker compose exec inform /unifi-go devices --socket=/runtime/control.sock
docker compose exec inform /unifi-go device --socket=/runtime/control.sock --device="$DEVICE_MAC"
docker compose exec inform /unifi-go clients --socket=/runtime/control.sock --device="$AP_MAC"
docker compose exec inform /unifi-go ports --socket=/runtime/control.sock --device="$SWITCH_MAC"
```

Snapshots contain reported observations. Missing fields remain absent; desired
settings do not fill them. Switch VLAN and PoE mode observations appear only when
the device reports those fields.

Restart without discarding the mounted state:

```sh
docker compose restart inform
```

Device keys, full baselines, typed identities, and descriptors reload. Reports and
queued commands disappear. Fresh informs restore observations. Reapply configuration
explicitly if a command was pending when the controller restarted.

## Sync a UniFi Network Application

Sync copies the configuration records a UniFi Network Application holds, in
either direction, and shows the difference for the destination before and after
it writes. It carries every collection the controller serves, not only WiFi:
networks, port profiles, firewall rules and groups, port forwards, routing,
RADIUS profiles, user groups, WLAN groups, deep packet inspection groups,
hotspot records, site settings, client records, and adopted devices.

Put the controller account in two owner-only files, then read the controller
into a local directory:

```sh
umask 077
CONTROLLER='https://<controller IPv4 address>:8443'
unifi-go sync pull --controller-url="$CONTROLLER" --site=default \
    --username-file=state/unifi-user --password-file=state/unifi-password \
    --dir=state/controller --dry-run
```

Dry run prints the difference and writes nothing. Drop `--dry-run` to store the
records. Each record becomes one JSON file at
`<dir>/<site>/<collection>/<identity>.json`.

Edit the stored files, then write them back:

```sh
unifi-go sync push --controller-url="$CONTROLLER" --site=default \
    --username-file=state/unifi-user --password-file=state/unifi-password \
    --dir=state/controller --dry-run
```

Use `--collections=wlanconf,device` to sync a subset, and `--insecure` when the
controller presents its own certificate. Add `--prune` to remove the destination
records the source no longer holds; without it neither direction removes
anything.

The stored files hold the controller's real WiFi passphrases and shared secrets,
so keep that directory private. The default `state/controller` sits under the
ignored `state/` directory, which keeps stored secrets out of version control.

To learn more about what the sync covers, how it matches records across
controllers, and what it deliberately leaves alone, see
[Controller record sync](docs/sync.md).

## Validate captures

Run the isolated live acceptance flow:

```sh
UNIFI_LIVE_E2E=1 go test ./integration -run '^TestLiveAPSwitch$' -count=1 -v -timeout=15m
```

The flow builds the actual controller and a test-only patched unifi-emu 0.5.5,
creates isolated Docker resources, and preserves a private run with packet capture,
image identities, command results, patch copies, and a SHA-256 manifest. It removes
only its own containers and network. Keep the preserved run private.

Compare an existing physical capture with its independent pixiedust transcript:

```sh
CAPTURE_RUN='/absolute/path/to/private/capture/run'
UNIFI_CAPTURE_RUN="$CAPTURE_RUN" go test ./integration -run '^TestCapturedTraffic$' -count=1 -v
```

Set `CAPTURE_RUN` to the absolute private run directory containing the capture, key
file, and transcript. The test reports counts without printing decoded payloads.
