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

The latest physical typed Apply reports both target virtual access points and the
requested radio settings: channel 6 at 20 MHz and 11 dBm on 2.4 GHz, and channel 44
at 40 MHz and 12 dBm on 5 GHz. The current error is empty and SSH access is restored.
Both radios report zero clients, so client association remains pending.

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
the selected AP and a typed VLAN capability for the selected switches. These added
fields are test contracts, not physical firmware evidence. It does not generate clients or
simulate forwarding or electrical power. Results from this derivative are
patched-emulator evidence.

The live flow passed with a U6EXT AP, an S216150 switch reporting 18 ports, and an
S224250 switch reporting 26 ports. Each device completed set-adopt and reported the
version returned by typed Apply. Decrypted replies contain WPA2, VLAN 20, explicit
radio settings, and switch access, tagged uplink, and PoE-off configuration.

Restart validation paused the emulators, queued a marked command, and restarted
the controller. Registering another synthetic identity forced the restarted process
to save its loaded device records. Keys and desired configuration survived that
rewrite; observations and queues did not survive restart. Fresh informs restored
snapshots without replaying the marked command.
Private evidence preserves captures, exact image identities, patch copies,
operation results, and a SHA-256 manifest.

Subprocess checks sent SIGINT after resource creation and SIGTERM while emulators
were paused. Both subprocesses failed through cleanup, finalized captures, preserved
manifests, and left no generated containers or network.

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

Desired configuration versions identify queued commands. Snapshot versions come
from device reports. In-process encrypted reports and emulator reflections do not
prove physical behavior.

## Unverified limits

No captured station report proves a client associated with the requested WPA2
network.

No user-owned switch has been tested. Physical VLAN forwarding and PoE power
remain unverified. Switch VLAN and PoE mode decoding is verified against the patched
emulator report contract; it does not establish physical switch observations.

The preserved failed physical capture stopped on capture-file ownership and is
diagnostic evidence only. Setup chronology, old host addresses, and previous
container health do not establish current acceptance.
