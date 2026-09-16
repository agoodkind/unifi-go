# Validation evidence

Physical AP, Network Server reference, live emulator, and automated tests establish
different claims. No physical switch or client-association proof is available.

## Physical AP with an imported key

The preserved physical `UAP-AC-PRO` exchange proves accepted configuration from
unifi-go using an existing inform key. It does not prove fresh-reset adoption with
the default key.

The first Go replies produced the device's `Decrypt Error`. Matching the captured
Network Server framing corrected this: TNBU version 0, payload version 1, and
uncompressed AES-GCM replies. The AP then reported `cfgversion=unifi-go-1` and
continued informing without the error.

The accepted configuration installed generated SSH credentials. A later successful
SSH connection using those credentials proves that credential configuration applied.
SSH was a recovery operation, not the Go controller's adoption transport.

On September 13, 2026, read-only device inspection found the selected legacy
network's one authentication record already had BSS Transition disabled. Six peer
authentication records retained their saved values. All 557 radio, wireless,
authentication, bridge, VLAN, and interface records matched the submitted baseline,
and all seven virtual interfaces were running. A fresh authenticated inform reported
the desired version with an empty queue. This verifies a pre-existing physical fix;
this task did not apply it or replace the active controller.

## Physical configuration dry run

A separately built branch controller used an owner-only copy of current device
state. It authenticated a captured current inform through its local HTTP listener;
the replayed response was never sent to the physical device. The active service
continued running throughout the check.

The old desired projection contained `ssh: null`, which the current typed API rejects
as an unsupported clear. Explicit import of the exact complete bodies with current
network and radio identities established usable ownership in the shadow controller.
No policy values were reconstructed from observations.

The actual CLI dry run returned zero added, one changed, and zero removed records.
Independent compilation verified that only configuration-version metadata changed;
every policy record was identical. Preview left state bytes, the empty queue, and
the reported version unchanged. The active state also remained byte-identical.
Private evidence preserves the request, opaque token, full candidate, current inform,
device inspection, and a recoverable state copy.

## Historical physical protocol evidence

Reproduced channel/width pairs on U7PG2 firmware 6.8.2.15592 supply a narrow
compatibility exception when required lists are absent. On 2.4 GHz, the supported
pairs are automatic/20 MHz, 6/20 MHz, 11/20 MHz, and 6/40 MHz. On 5 GHz, they are
automatic/40 MHz, 44/40 MHz, and 157/40 MHz. Physical results establish the explicit
20 MHz pairs and the explicit 5 GHz pairs. The seeded Network Server with the
same-model emulator establishes 6/40 MHz. Power still requires reported bounds.
Explicit reported capability lists are validated independently of model identity.

The AP stopped informing after receiving a bracketed IPv6 inform URL. Restoring IPv4
resumed informs and cleared the reported error. Successful IPv6 packet exchange
alone did not establish IPv6 inform-URL compatibility.

The initial Network Server capture contains 3,252 packets in each of two independent
physical recordings. The imported database key decrypts 24 messages without decode
failures. The transcript contains 13 physical device payload occurrences, eight
noop replies, three setparam replies, and one upgrade reply. The later Go
validation run preserves 3,544 physical packets. These are historical recordings,
not evidence of current device reachability.

The physical capture preserves encrypted SSH traffic, but not the plaintext key
delivered through SSH. It preserves an upgrade command and later informs, but not
the device's direct firmware download.

## Seeded Network Server reference

A real seeded Network Server 10.6.101 exchanged encrypted informs with unifi-emu
0.5.5. Captured configuration changes cover AP wireless creation, VLAN, channel,
width, and power; switch changes cover native VLAN, tagged VLAN, disabled ports,
and PoE off and automatic modes.

The emulator originally reported `poe_caps` without `port_poe`. A test-only patch
exposed the existing capability. The real Network Server then emitted
`switch.port.2.poe=shutdown` and `switch.port.2.poe=auto`. This establishes the
controller's configuration vocabulary, not physical power delivery.

Sanitized fixture generation correlates each device's report, controller reply,
and next report. It publishes synthetic identities and secret placeholders.
The original private recordings remain separate from public fixtures.

## Live unifi-go and emulator acceptance

The isolated live test builds the actual controller container and a derivative of
pinned unifi-emu 0.5.5. It selects a dual-radio AP and two PoE switch inventories
with different port counts by capabilities. Model names are test inputs, not a
support allowlist.

Upstream unifi-emu does not reflect `system_cfg` into later radio or port reports.
The test-only derivative parses the tested radio, native VLAN, tagged VLAN, and
PoE mode records into report state. It adds synthetic channel and width lists for
the selected AP, a typed VLAN capability for the selected switches, and an explicit
family field. Imported switch fixtures also receive synthetic port status and native
VLAN records. These additions are test contracts, not physical firmware evidence.
It does not generate clients or simulate forwarding or electrical power.
Results from this derivative are
patched-emulator evidence.

The September 13 live flow used one dual-radio AP and two switch inventories reporting
different port counts. It later added and fully configured a second eligible AP.
Each device completed set-adopt. The public client imported complete reference bodies
and explicit projections through the actual controller socket. It previewed and
applied policy through the same transaction used by the executable resource commands.

The first AP copied a dual-radio WiFi network through `wifi add` without a device
selector. The decrypted reply retained both radio targets, distinct source and copied
credentials, and unchanged radio policy. A second mutation stopped while the copied
configuration was pending. Later `wifi set`, `radio set`, and `port set` changes reached
matching reports. An injected mismatched report version stopped the next mutation
without changing state or queueing work. A deliberate full Apply restored ownership.
The per-network legacy BSS Transition disable and peer settings survived every change.

The combined recording contains 254 decrypted messages. Seven intervals returned
encrypted noops. Ten delivered management and system map pairs matched expectations
derived from the original imported maps plus only the requested resource changes.
Those expectations never read the controller's compiled or persisted maps. Unknown
records and omitted policy survived. Adding the second AP made omitted-device
selection fail without choosing either AP.

Restart validation paused the emulators and queued a typed radio change without its
matching authenticated report. Keys, complete baselines, bindings, desired
configuration, and the pending desired version survived restart. Observations, the
queue, and acknowledgement state did not. Two fresh informs received no replay. A
deliberate reapply of the persisted desired configuration succeeded before the device
reported that version, which proves the old acknowledgement state cleared. After the
matching report, a new radio mutation also succeeded. An unrelated second change in
each family retained the first change. The recorder reattached after the controller
restarted; both recordings remain beside their combined capture.
Private evidence preserves captures, exact image identities, patch copies,
operation results, and a SHA-256 manifest.

Subprocess checks sent SIGINT after resource creation and SIGTERM while emulators
were paused. Both subprocesses failed through cleanup, finalized captures, preserved
manifests, and left no generated containers or network.

The required physical temporary WiFi removal and re-addition was not run because that
specific disruptive action still requires operator approval. Existing read-only
physical evidence remains separate from the emulator acceptance.

## Automated fixture and socket validation

Fixture tests run the public capture generator against encrypted packets and
decode its outputs. Compiler integration tests use sanitized captured configuration.
The typed control integration uses real Unix HTTP sockets, encrypted informs, the
public client, CLI operations, and both compilers. These tests establish software
behavior, not live device application.

The shared checks, race tests, fixture generation test, and Docker build passed.
Independent capture comparison passed for 24 messages in the initial physical run
and 104 messages in the later run. The live test requires an explicit environment
variable; an ordinary skipped invocation is not acceptance evidence.

Compiled versions alone do not prove device application. Snapshot versions come
from device reports. In-process encrypted reports and emulator reflections do not
prove physical behavior.

## Controller record sync

On September 16, 2026, a live UniFi Network Application 10.6.101 answered a probe
of 27 candidate REST collections. Seventeen answered with a success envelope and
are registered; `apgroup`, `staticroute`, `heatmap`, `map`, `tag`, `schedule`, and
`broadcastgroup` were rejected and are not. The device collection is read from
`stat/device` and written at `rest/device`, which the probe confirmed separately.

A pull of that controller stored 53 records across eight collections as mode-0600
files under mode-0700 directories. A push immediately afterwards reported no
differences, which establishes that a stored record round trips without drift.

A push then renamed one device record on the live controller. The difference
printed before the write named the change, and the difference printed after the
write came from re-reading the controller, which establishes that the reported
result reflects the controller rather than the request. The change was reverted
by the same path and the live value confirmed by direct query.

Redaction was verified against real controller values: a RADIUS shared secret
nested inside an authentication server entry, the mesh key, and two WiFi
passphrases all rendered as digests, while `passphrase_autogenerated` stayed
readable as a boolean.

No second controller has been tested. Moving a record between two controllers is
unverified, and records that reference another record by the controller's own
identifier are expected to need remapping first.

## Shadow and authoritative modes

On September 16, 2026, a shadow controller started beside the live UniFi Network
Application. It reported `mode=shadow` with no inform address and bound nothing,
which `lsof` confirmed against the chosen address.

Importing from the stored records registered the live access point's inform key,
and the stored device state then carried a 32 character key for that hardware
address. The rendered import printed a digest rather than the key.

Promotion against a free address bound it, answered a request on the inform
path, and reported the bound address. Demotion released it, and a later
connection to that address was refused.

Promotion against the address the live controller publishes bound it on the
first attempt, because a listener asks for address reuse and a specific address
binds beside a published wildcard address. That attempt was released at once,
the live access point stayed connected, and promotion now connects to the
address first and refuses while anything answers. A second attempt against the
same live address was refused and left the controller shadowed.

No device has been moved from the live controller to unifi-go. Taking over real
device traffic is unverified.

## Unverified limits

No captured station report proves a client associated with the requested WPA2
network.

No user-owned switch has been tested. Physical VLAN forwarding and PoE power
remain unverified. Switch VLAN and PoE mode decoding is verified against the patched
emulator report contract; it does not establish physical switch observations.

The preserved failed physical capture stopped on capture-file ownership and is
diagnostic evidence only. Setup chronology, old host addresses, and previous
container health do not establish current acceptance.
