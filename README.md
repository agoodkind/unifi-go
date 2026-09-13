# Run unifi-go

Use unifi-go to adopt and configure access points and switches through encrypted
informs. It complements [unifi-emu](https://github.com/jamesbraid/unifi-emu), which
simulates devices and supplies the reused protocol library.

## Start the controller

Install Docker, Go matching the module version, and Make. Install TShark and patch
before running capture acceptance.

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
with the assigned key, the controller sends the initial configuration. Adoption
generates and saves device SSH credentials.

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

Point the device at this controller and wait for its report. Apply the complete
desired configuration afterward. Omitted wireless networks are not preserved.

## Configure an access point

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
reported minimum and maximum bounds. Omit `channel` to select automatically.
Save the configuration in the mounted state directory under the filename used below:

```sh
docker compose exec inform /unifi-go apply ap \
    --socket=/runtime/control.sock --device="$DEVICE_MAC" --file=/state/ap.json
```

The returned version identifies queued configuration. It does not prove the device
applied it. Typed Apply changes SSH credentials only when an explicit `ssh` object
supplies `username` and a `password` secret-file reference.
Later applications without `ssh` and controller restarts preserve that latest account.

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

Device keys, desired configuration, and descriptors reload. Reports and queued
commands disappear. Fresh informs restore observations. Reapply configuration
explicitly if a command was pending when the controller restarted.

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
