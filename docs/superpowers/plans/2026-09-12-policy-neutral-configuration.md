# Policy-Neutral Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve full device configuration through policy-neutral typed changes, complete the legacy-network BSS Transition fix, then complete the existing generic resource plan.

**Architecture:** Persist one complete configuration baseline with a typed projection and stable wire bindings. Compile explicit operator policy as an overlay, keep raw delivery exact, and share one atomic transaction between previews, full Apply, and later resource mutations.

**Tech Stack:** Go 1.27.1, go-makefile, Unix-socket HTTP, JSON state, unifi-emu/inform v0.5.5, Docker Compose, pixiedust, and TShark.

**Spec:** [Policy-neutral configuration design](../specs/2026-09-12-policy-neutral-configuration-design.md)

## Global Constraints

- Support exactly APs and switches. Gateways remain excluded.
- Do not add a model admission allowlist, fixed radio count, fixed port count, or fixed PoE layout.
- An omitted BSS field must never default to enabled.
- Operator input selects policy; profiles contain mappings and capability constraints only.
- Preserve unknown and unspecified baseline records across typed calls and restart.
- Raw ApplyConfig keeps exact supplied version and bodies without profile restrictions.
- Keep secrets and physical identifiers out of public previews, logs, and tracked evidence.
- Keep the old resource plan intact and complete every task after this prerequisite.
- Use the shared make targets exactly; do not override cache variables or weaken gates.
- Keep unit tests minimal. Extend compiler integration, real socket, persistence, and live tests.
- Record task evidence and remaining acceptance work in a private progress file; an unchecked hardware gate stays incomplete.

---

## Establish the implementation structure

The existing documentation already separates design specifications from executable plans. The requested new files use those existing homes. The design owns the behavior contract; this plan owns implementation steps and links to the preserved subsequent plan once in Task 8.

Current source persists `Device.LastSetParam` but typed apply regenerates defaults. The AP compiler initializes omitted BSS Transition to enabled. Raw queueing changes the last submitted reply while leaving older typed desired state intact. `Reply.validate` also admits only `set-adopt` commands. The following tasks change these verified behaviors.

Create focused baseline, presence, composition, and preview modules. Keep adoption, encryption, and the existing socket infrastructure in place. New modules remain in the current packages so callers do not acquire a second controller or transport.

### Task 1: Represent explicit policy and persisted baselines

**Files:**

- Create: [network/presence.go](../../../network/presence.go)
- Modify: [network/config.go](../../../network/config.go)
- Modify: [network/config_test.go](../../../network/config_test.go)
- Modify: [network/errors.go](../../../network/errors.go)
- Create: [internal/controller/baseline.go](../../../internal/controller/baseline.go)
- Modify: [internal/controller/controller.go](../../../internal/controller/controller.go)
- Test: [cmd/unifi-go/typed_integration_test.go](../../../cmd/unifi-go/typed_integration_test.go)
- Modify: the existing AP and switch compiler call sites, typed controller call sites, and Go fixture constructors enumerated in Task 2. The presence-type migration must compile across those consumers in this task.

**Interfaces:**

Consumes `controller.Open(stateFile, advertise string, registries ...profile.Registry)` and `Device.LastSetParam`. Produces these concrete types; the baseline's body format remains exact text:

```go
// package network
type Optional[T any] struct {
    Present bool
    Null    bool
    Value   T
}
func Supplied[T any](value T) Optional[T]
func Cleared[T any]() Optional[T]
func (value Optional[T]) IsZero() bool
func (value Optional[T]) MarshalJSON() ([]byte, error)
func (value *Optional[T]) UnmarshalJSON(data []byte) error

// package profile; add to the existing profile declarations in Task 1.
type ResourceBinding struct {
    Kind       string   `json:"kind"`
    Identity   string   `json:"identity"`
    RadioID    string   `json:"radio_id,omitempty"`
    Prefixes   []string `json:"prefixes"`
}

// package controller
type ConfigurationBaseline struct {
    SchemaVersion uint16                `json:"schema_version"`
    Config        network.Config        `json:"config"`
    TypedReady    bool                  `json:"typed_ready"`
    Bindings      []profile.ResourceBinding `json:"bindings,omitempty"`
}
func baselineFromLegacy(device Device) (*ConfigurationBaseline, error)
```

Add `Baseline *ConfigurationBaseline` to `Device` with `json:"baseline,omitempty"`. Add safe error codes `baseline_required`, `baseline_unusable`, `policy_required`, `configuration_pending`, `configuration_drift`, and `preview_stale` to `network.ControlError`. Preserve existing safe field filtering and never embed invalid record text in a public error.

- [ ] **Step 1: Extend the existing socket integration with persisted presence cases.**

Inside `TestTypedControlIntegration`, use its real state file, controller, socket, client, encrypted exchanges, and temporary credential files. Add cases for an absent key, an explicit false, an explicit null VLAN, and an omitted enum. Marshal each through the client and reload state through `Open`; assert the three states remain distinct. Include old JSON fixtures that do not have `bss_transition` and retain `LastSetParam` byte-for-byte.

```go
var omitted network.Optional[bool]
disabled := network.Supplied(false)
untagged := network.Cleared[network.VLANID]()
if omitted.Present || !disabled.Present || disabled.Value || !untagged.Null {
    t.Fatal("policy presence changed")
}
```

The presence assertions accompany the socket round trip, not a standalone suite that only tests the helper.

- [ ] **Step 2: Run the integration to prove the new types are absent.**

```sh
go test ./cmd/unifi-go -run '^TestTypedControlIntegration$' -count=1 -v
```

Expected: compilation fails on the new presence or baseline types.

- [ ] **Step 3: Implement presence-aware policy without changing JSON names.**

Wrap `CountryCode`, `Networks`, `Radios`, `Ports`, and `SSH` in `Optional`. Keep resource identity fields plain: WiFi `Name`, radio `Band` and later `ID`, and port `Index`. Wrap each policy field in those resources, including nested `Security`, `Power`, security `Mode` and `PSK`, power `Mode` and `DBm`, `Enabled`, `Bands`, later `RadioIDs`, `VLAN`, `Channel`, `WidthMHz`, `NativeVLAN`, `TaggedVLANs`, `PoE`, and `BSSTransition`. Use `omitzero` to omit absent fields when encoding.

```go
type WiFiSecurity struct {
    Mode Optional[WiFiSecurityMode] `json:"mode,omitzero"`
    PSK  Optional[SecretFile]       `json:"psk,omitzero"`
}
type WiFiNetwork struct {
    Name          string                      `json:"name"`
    Enabled       Optional[bool]              `json:"enabled,omitzero"`
    VLAN          Optional[VLANID]            `json:"vlan,omitzero"`
    Bands         Optional[[]RadioBand]       `json:"bands,omitzero"`
    BSSTransition Optional[BSSTransitionMode]  `json:"bss_transition,omitzero"`
    Security      Optional[WiFiSecurity]      `json:"security,omitzero"`
}
```

Implement JSON methods with `encoding/json`; plain values remain plain JSON, not `{Present,Null,Value}` objects. Reject malformed/trailing values. Allow null only for VLAN and channel at this stage. Split validation into supplied-value validation before composition and required-value checks when creating new resources. Adapt existing Go fixture literals with `network.Supplied` so explicit previous test policy stays explicit. Update compiler accessors and typed controller accessors in the same commit. Keep their current fully supplied behavior until Task 2 replaces generation. Do not treat zero as omission.

- [ ] **Step 4: Add migration and atomic baseline state.**

Read both `last_setparam` and the loader's existing legacy `config` alias. Preserve exact body strings. Initialize schema version 1. Mark typed ownership ready only when complete parseable bodies, a matching stored desired version, and unambiguous projection bindings agree. Keep missing/unparseable baselines available to raw transport and return a safe typed error later. Never run a compiler from migration. Keep load read-only; commit the migrated record through the next successful state write.

```go
if device.Baseline == nil && device.LastSetParam != nil {
    baseline, err := baselineFromLegacy(device)
    if err == nil {
        device.Baseline = baseline
    }
    // A legacy reply remains available to raw transport on typed parse failure.
}
```

Use the existing atomic state writer and its owner-only modes. Preserve the original device value until persistence succeeds. Add no command replay.

- [ ] **Step 5: Verify migration failures and commit the slice.**

Add load and socket cases for no baseline, malformed/duplicate-key baseline, a later raw version than typed state, and failed persistence. Assert raw delivery still works and migration preserves exact bodies without enqueueing. Assert the new baseline's typed-ready status is false when ownership cannot be established. Task 2 activates the typed baseline guards; do not require those future guards to pass this task's tests.

```sh
go test ./cmd/unifi-go -run '^(TestTypedControlIntegration|TestConfigVersionUXIntegration)$' -count=1 -v
make check
```

Expected: both commands pass. Commit only this task's source and integration changes with `git commit -S` and `Co-authored-by: Codex <noreply@openai.com>`.

### Task 2: Compose typed fields over complete configuration

**Files:**

- Modify: [internal/profile/profile.go](../../../internal/profile/profile.go)
- Modify: [internal/profile/registry.go](../../../internal/profile/registry.go)
- Create: [internal/profile/composition.go](../../../internal/profile/composition.go)
- Modify: [internal/configmap/configmap.go](../../../internal/configmap/configmap.go)
- Modify: [internal/profile/ap/compiler.go](../../../internal/profile/ap/compiler.go)
- Modify: [internal/profile/switches/compiler.go](../../../internal/profile/switches/compiler.go)
- Test: [integration/ap_compiler_test.go](../../../integration/ap_compiler_test.go)
- Test: [integration/switch_compiler_test.go](../../../integration/switch_compiler_test.go)
- Modify: the existing typed controller apply call sites and socket integration from Task 1 so the new compiler signatures and full-baseline persistence work before this task commits.

**Interfaces:**

Consumes presence-aware configs, Task 1's `ResourceBinding`, and baseline bodies. Produces these profile interfaces, replacing the old compiler signatures in their existing packages:

```go
type CompilationInput struct {
    Baseline SetParam
    AP       *network.APConfig
    Switch   *network.SwitchConfig
    Bindings []ResourceBinding
}
type Compilation struct {
    Param    SetParam
    AP       *network.APConfig
    Switch   *network.SwitchConfig
    Bindings []ResourceBinding
}
// Add these signatures to APCompiler and SwitchCompiler respectively.
Compile(DeviceDescriptor, CompilationInput, network.APConfig, SecretReader) (Compilation, error)
Compile(DeviceDescriptor, CompilationInput, network.SwitchConfig, SecretReader) (Compilation, error)
// Update the existing registry methods to match.
func (registry Registry) CompileAP(DeviceDescriptor, CompilationInput, network.APConfig, SecretReader) (Compilation, error)
func (registry Registry) CompileSwitch(DeviceDescriptor, CompilationInput, network.SwitchConfig, SecretReader) (Compilation, error)
```

Keep `Supports` and `Decode` unchanged. `CompilationInput.AP` and `.Switch` describe the prior typed projection, while the config argument carries only this request's supplied policy. One family pointer is nonnil in each result.

- [ ] **Step 1: Extend both existing compiler integrations with preservation scenarios.**

Use sanitized complete Network Server fixtures as explicit baselines. Seed different roaming values for three WLANs, unknown top-level records, unknown per-WLAN records, a custom timezone, SSH policy, and unknown switch-port settings. Request one field change. Compare complete decoded maps against a clone with only the requested and mandatory dependent keys changed.

```go
baseline.System["locale.timezone"] = "operator-zone"
baseline.System["operator.unmodeled"] = "retain"
before := baseline.System.Clone()
input := profile.CompilationInput{Baseline: baseline, AP: &config, Bindings: bindings}
compiled, err := registry.CompileAP(descriptor, input, request, fileSecrets{})
if err != nil {
    t.Fatal("baseline composition failed")
}
if compiled.Param.System["operator.unmodeled"] != before["operator.unmodeled"] {
    t.Fatal("unrequested policy changed")
}
```

Define `baseline`, `bindings`, and `request` inside the existing fixture test from its parsed fixture, radio inventory, and named synthetic WLANs. Include add/remove/reorder operations, explicit false, explicit null VLAN/channel, empty versus omitted collections, unchanged unsupported security, unrecognized models with sufficient capabilities, and missing capabilities for only the affected setting.

- [ ] **Step 2: Run both integrations and verify preservation fails before implementation.**

```sh
go test ./integration -run '^(TestAPCompilerFromNetworkServerFixture|TestSwitchCompilerFromNetworkServerFixture)$' -count=1 -v
```

Expected: compilation failure on the new interface, followed by observable preservation failures as call sites are adapted.

- [ ] **Step 3: Implement explicit overlay and durable resource bindings.**

Parse only typed baselines with `configmap.Parse`, clone both maps, and resolve existing WLAN records by exact name plus physical-radio interface. Associate matching authentication, interface, and bridge references. Keep stable binding identities across reordering. Reject duplicate matches; never choose the first record. Copy unknown owned records when adding a resource and remap their record prefixes and known references. Delete only the removed binding's records and now-unused known references.

```go
system := input.Baseline.System.Clone()
management := input.Baseline.Management.Clone()
if wifi.BSSTransition.Present {
    if err := system.Set(aaaPrefix+"bss_transition", string(wifi.BSSTransition.Value)); err != nil {
        return profile.Compilation{}, err
    }
}
```

Replace `baseSystem`, `writeSystemDefaults`, and blanket `writeWireless` dictionaries with mappings activated by supplied fields or preserved baseline records. Preserve WPA, rate, DTIM, WMM, mesh, filter, timezone, service, bridge, PoE, and telemetry choices on omission. Keep mandatory wire dependencies explicit and cover their changed keys in fixture expectations. Do not revalidate unsupported untouched settings as though newly requested.

Adapt the controller's existing `apply` method now to pass its parsed persisted baseline and prior projection, persist the returned full bodies and bindings atomically, and reject missing/unusable baselines with the new safe errors. Seed the existing socket fixtures with explicit complete baseline records. Do not wait until Task 5 to repair these compiler call sites. Task 5 extracts the shared transaction and adds preview/pending behavior after baseline apply already works.

- [ ] **Step 4: Hash the final composed content and keep inputs immutable.**

Use `CanonicalVersion` on the final full result after policy overlay. Do not hash the request alone. Clone optional nested slices, pointers, maps, and resource bindings without a JSON round trip. An unchanged baseline and effective request produce the same version; a changed unknown retained record changes the version. Required new-resource policy must come from input or an explicit copy source.

```go
param := profile.SetParam{Management: management, System: system}
version, err := profile.CanonicalVersion(param)
if err != nil {
    return profile.Compilation{}, err
}
param.Version = version
```

- [ ] **Step 5: Run compiler, race, and shared checks, then commit.**

```sh
go test ./integration -run '^(TestAPCompilerFromNetworkServerFixture|TestSwitchCompilerFromNetworkServerFixture)$' -count=1 -v
go test -race ./network ./internal/profile/... ./internal/configmap
make check
```

Expected: all pass with full preservation comparisons. Create one signed commit for this slice.

### Task 3: Complete the BSS Transition fix

**Files:** Use the existing network configuration and validation tests, AP compiler, and AP compiler integration named in Tasks 1 and 2. Preserve their four current uncommitted source changes while adapting presence semantics. Extend the existing controller socket integration from Task 1.

**Interfaces:** Consumes `WiFiNetwork.BSSTransition Optional[BSSTransitionMode]`, `BSSTransitionEnabled`, `BSSTransitionDisabled`, and Task 2 composition. Produces per-WLAN omission-preserving mapping to every bound `aaa.N.bss_transition` record.

- [ ] **Step 1: Replace the existing default-enabled assertion with baseline-specific cases.**

Run one compiler scenario with two radio targets for the legacy WLAN, one peer explicitly enabled in the baseline, one peer disabled, and one peer with no BSS key. Set only the legacy WLAN to disabled. Then apply an unrelated field request with BSS omitted and compose again after serializing and loading the baseline.

```go
request.Networks.Value[legacyIndex].BSSTransition = network.Supplied(network.BSSTransitionDisabled)
// Each index is resolved from the synthetic WLAN's binding, not array order.
for _, prefix := range legacyAAAPrefixes {
    if compiled.Param.System[prefix+"bss_transition"] != "disabled" {
        t.Fatal("legacy network retained BSS Transition")
    }
}
if _, exists := compiled.Param.System[absentPeerPrefix+"bss_transition"]; exists {
    t.Fatal("omitted BSS Transition acquired a default")
}
```

Construct prefixes from fixture bindings inside the existing test. Compare enabled and disabled peers against their pre-change values. An invalid explicit enum must leave baseline, projection, and queue unchanged through the socket.

- [ ] **Step 2: Verify the current fallback fails the new case.**

```sh
go test ./integration -run '^TestAPCompilerFromNetworkServerFixture$' -count=1 -v
```

Expected: if Task 2 already removed the fallback, the compiler cases pass. Temporarily reintroduce the old enabled fallback in the isolated worktree and confirm the absent or disabled peer assertion fails, then remove that mutation. Do not fabricate an initial failure when the earlier task already fixed it.

- [ ] **Step 3: Retain the existing fix and remove its fallback.**

Keep the enum and explicit enabled/disabled validation. Remove `bssTransition := network.BSSTransitionEnabled` and the blanket BSS map entry. Write the key only for a present valid field, using Task 2's binding-aware overlay. Omission never deletes or supplies the key. For a fresh resource without a baseline choice, preserve absence unless verified protocol requirements demand explicit input.

```go
if wifi.BSSTransition.Present && wifi.BSSTransition.Null {
    return profile.Compilation{}, &network.ControlError{Code: network.InvalidConfig, Field: ""}
}
```

- [ ] **Step 4: Prove repeated socket applies and restart preserve every peer.**

Extend `TestTypedControlIntegration` with a complete persisted baseline fixture, typed legacy-network disable, decrypted reply verification, matching inform, controller reopen, fresh inform, and an unrelated typed request with BSS omitted. Assert the last complete persisted body and delivered reply preserve all peer values. Use a synthetic `fixture-legacy` network in tracked tests. The public baseline-import API is added in Task 4; use the state loader for this task's starting fixture. Do not print the compared bodies.

- [ ] **Step 5: Run checks and commit the retained fix.**

```sh
go test ./integration -run '^TestAPCompilerFromNetworkServerFixture$' -count=1 -v
go test ./cmd/unifi-go -run '^TestTypedControlIntegration$' -count=1 -v
make check
```

Expected: all pass. Commit the completed BSS fix as a signed logical slice; do not discard the original uncommitted intent.

### Task 4: Keep transport generic and raw application exact

**Files:**

- Modify: [internal/controller/protocol.go](../../../internal/controller/protocol.go)
- Modify: [internal/controller/control.go](../../../internal/controller/control.go)
- Modify: [internal/controller/system.go](../../../internal/controller/system.go)
- Modify: [network/client.go](../../../network/client.go)
- Modify: [cmd/unifi-go/main.go](../../../cmd/unifi-go/main.go)
- Modify: [cmd/unifi-go/typed.go](../../../cmd/unifi-go/typed.go)
- Modify: the controller persistence, baseline, and socket integration files from Task 1.

**Interfaces:**

Consumes existing `Controller.Queue(mac string, command Reply) error` and `Client.ApplyConfig(context.Context, DeviceID, Config) (ConfigVersion, error)`. Produces these public methods and socket operations:

```go
// package network
type Command struct {
    Name       string                     `json:"name"`
    Parameters map[string]json.RawMessage `json:"parameters"`
}
type BaselineImport struct {
    Config Config        `json:"config"`
    AP     *APConfig     `json:"ap,omitempty"`
    Switch *SwitchConfig `json:"switch,omitempty"`
}
func (client *Client) SendCommand(context.Context, DeviceID, Command) error
func (client *Client) ImportBaseline(context.Context, DeviceID, BaselineImport) error
```

Add `command` and `baseline-import` operations to both independent socket envelope definitions. Add `Parameters map[string]json.RawMessage` to the internal reply with custom JSON flattening so device command fields retain their wire names. Reject collisions with `_type`, `cmd`, and transport-owned server time; permit all other valid JSON command parameters. Keep key/URI validation for explicit `set-adopt`.

- [ ] **Step 1: Extend raw and socket integration before implementation.**

Extend `TestGenericConfigControlIntegration` with exact order, blank lines, duplicate records, unfamiliar security settings, unknown keys, and non-ASCII valid UTF-8. Assert byte equality on decrypted `ManagementConfig` and `SystemConfig`, supplied version equality, and persisted baseline equality. Existing malformed UTF-8 and surrogate tests remain.

```go
config := network.Config{
    Version: "operator-version",
    Management: "z=last\na=first\n",
    System: "unknown.security=operator\nrepeat=one\nrepeat=two\n",
}
_, err := client.ApplyConfig(t.Context(), id, config)
if err != nil {
    t.Fatal("raw configuration was restricted")
}
```

Also send an unfamiliar command through the public method and decrypt its next inform reply. Assert preserved name and structured parameters without invoking a profile. Confirm it does not replace the baseline and does not replay after restart.

- [ ] **Step 2: Run the raw tests to identify changed contracts.**

```sh
go test ./cmd/unifi-go -run '^(TestGenericConfigControlIntegration|TestRawConfigSocketEncoding|TestConfigVersionUXIntegration)$' -count=1 -v
```

Expected: existing exact raw tests pass, while new command and baseline ownership assertions fail before implementation.

- [ ] **Step 3: Persist exact raw bodies and invalidate typed ownership atomically.**

In `Queue`, keep validation transport-only. For raw setparam, save the exact reply and baseline together, clear typed-ready bindings and stale desired projections/version, and restore the previous device if saving fails. Do not call `configmap.Parse` from this path. Require explicit import before a typed call resumes ownership.

```go
previous := device
device.LastSetParam = &command
device.Baseline = &ConfigurationBaseline{
    SchemaVersion: 1,
    Config: network.Config{Version: network.ConfigVersion(command.ConfigVersion), Management: command.ManagementConfig, System: command.SystemConfig},
}
device.DesiredAP, device.DesiredSwitch, device.DesiredVersion = nil, nil, ""
```

Implement `ImportBaseline` as a locked, no-queue transaction that validates complete namespaces, exact family, explicit projected identities, and parseable records. Establish bindings and imported version without claiming application. A request containing both projections fails. Do not merge a partial raw reply with stale typed records. Invalid import leaves all prior bytes and queue entries unchanged.

- [ ] **Step 4: Remove policy selection from metadata and adoption.**

Reduce controller augmentation to demonstrated connection metadata. Preserve baseline SSH and policy fields. Remove implicit `preserveSSH` insertion and crash-reporting or `unifi.idp` defaults; retain a field only when reference evidence proves it mandatory connection metadata. Replace automatic generated-SSH installation in `Controller.Adopt` with an explicit operator option, updating its control-envelope and CLI caller. Keep encryption and adoption key rotation unchanged.

```go
// Required connection fields are overlaid only for typed delivery.
management["authkey"] = device.Key
management["inform_url"] = c.advertise
management["cfgversion"] = string(param.Version)
```

Add socket tests proving adoption does not activate SSH when the option is absent, while an explicit SSH request still works. Preserve existing owner-selected SSH through later typed changes.

- [ ] **Step 5: Run transport and shared checks, then commit.**

```sh
go test ./cmd/unifi-go -run '^(TestGenericConfigControlIntegration|TestRawConfigSocketEncoding|TestTypedControlIntegration|TestConfigVersionUXIntegration)$' -count=1 -v
go test -race ./internal/controller ./network ./cmd/unifi-go
make check
```

Expected: all pass, including existing encrypted CBC and GCM flows. Create a signed commit.

### Task 5: Share one atomic typed transaction and preview

**Files:**

- Modify: [internal/controller/typed.go](../../../internal/controller/typed.go)
- Create: [internal/controller/preview.go](../../../internal/controller/preview.go)
- Create: [network/preview.go](../../../network/preview.go)
- Modify: the control envelopes, public client, typed CLI, controller baseline, and socket integration already named.

**Interfaces:**

Consumes Task 2 compilers and Task 4 explicit baseline import. Produces:

```go
// package network
type PreviewToken string
type ConfigPreview struct {
    Token   PreviewToken `json:"token"`
    Added   uint32       `json:"added"`
    Changed uint32       `json:"changed"`
    Removed uint32       `json:"removed"`
}
func (client *Client) PreviewAP(context.Context, DeviceID, APConfig) (ConfigPreview, error)
func (client *Client) PreviewSwitch(context.Context, DeviceID, SwitchConfig) (ConfigPreview, error)
func (client *Client) ApplyAPPreview(context.Context, DeviceID, APConfig, PreviewToken) (ConfigVersion, error)
func (client *Client) ApplySwitchPreview(context.Context, DeviceID, SwitchConfig, PreviewToken) (ConfigVersion, error)

// package controller
func (c *Controller) compileLocked(Device, network.DeviceFamily, *network.APConfig, *network.SwitchConfig) (profile.Compilation, error)
func (c *Controller) commitCompiledLocked(Device, profile.Compilation) (network.ConfigVersion, error)
```

Existing full Apply methods remain callable without a preview token. Add `preview-ap` and `preview-switch` socket operations and an optional preview token on typed apply. Preview tokens are random, expire after five minutes, and persist only in memory. Associate tokens privately with request, baseline revision, relevant capabilities, and resolved secret bytes; never expose those values or their hashes.

- [ ] **Step 1: Add the preview/apply/restart scenario to the real socket integration.**

Read state bytes and queue length before and after preview. Assert equality, decrypt the next ordinary inform to prove no configuration was sent, then apply the same request with its token and inspect the full reply. Change baseline, capabilities, request, or credential-file bytes between preview and apply; each stale-token attempt must fail without a state or queue change.

```go
preview, err := client.PreviewAP(ctx, apID, apConfig)
if err != nil {
    t.Fatal("preview failed")
}
if preview.Token == "" {
    t.Fatal("preview token missing")
}
version, err := client.ApplyAPPreview(ctx, apID, apConfig, preview.Token)
if err != nil || version == "" {
    t.Fatal("previewed configuration was not queued")
}
```

- [ ] **Step 2: Run the new scenario before adding the methods.**

```sh
go test ./cmd/unifi-go -run '^TestTypedControlIntegration$' -count=1 -v
```

Expected: new methods are absent.

- [ ] **Step 3: Implement one locked composition transaction.**

Normalize and find the registered device; require completed adoption, exact AP/switch family, fresh authenticated report, and usable complete baseline. Reject queued or awaiting typed configuration. Compose from a deep clone and validate only requested affected settings. Full Apply may deliberately reconcile reported drift; later resource mutations must reject it. Persist complete composed bodies, typed projection, bindings, and version together before queueing. Roll back in-memory state on save failure.

```go
if c.awaiting[device.MAC] != "" || len(c.queues[device.MAC]) != 0 {
    return "", &network.ControlError{Code: network.ConfigurationPending, Field: ""}
}
```

Add the existing resource plan's awaiting map here. Clear it only on an authenticated matching reported version, never on queue consumption. Keep queues and awaiting empty after restart. If effective version is unchanged, persist representation changes without queueing or setting awaiting. Require fresh reports after reopen and retain the reported-version drift comparison for incremental calls.

- [ ] **Step 4: Implement side-effect-free preview and CLI flags.**

Run `compileLocked` for preview without calling `commitCompiledLocked`. Do not persist lazy migration during preview. Add `--dry-run` and `--preview-token-file` to AP and switch apply parsing; the latter reads the opaque token and is invalid with dry run. Print only `ConfigPreview` for dry run. Token application revalidates all inputs and commits the recomputed candidate only when unchanged.

```text
unifi-go apply ap --device ID --file CONFIG --dry-run
unifi-go apply ap --device ID --file CONFIG --preview-token-file TOKEN_FILE
unifi-go apply switch --device ID --file CONFIG --dry-run
```

These are syntax examples. Live checks obtain actual device and file values from private evidence rather than literal placeholders.

- [ ] **Step 5: Run socket, race, and shared checks, then commit.**

```sh
go test ./cmd/unifi-go -run '^(TestTypedControlIntegration|TestConfigVersionUXIntegration|TestGenericConfigControlIntegration|TestRawConfigSocketEncoding)$' -count=1 -v
go test -race ./network ./internal/controller ./cmd/unifi-go
make check
```

Expected: all pass. Cover concurrent callers with one successful state transition and one pending rejection, failed persistence with no queue, unchanged representation updates, stale previews, and restart composition. Create a signed commit.

### Task 6: Prove live compilation and legacy-network application

**Files:**

- Modify: [integration/ap_switch_test.go](../../../integration/ap_switch_test.go)
- Modify: [docs/evidence.md](../../evidence.md)
- Modify: [README.md](../../../README.md)

**Interfaces:** Consumes public baseline import, previews, token-checked Apply, and existing `TestLiveAPSwitch`. Produces a preserved emulator run and private physical AP evidence for the legacy network.

- [ ] **Step 1: Extend the existing live AP/switch flow with explicit baselines.**

Use isolated Network Server exchanges as baseline input for both emulated families. Import complete bodies and explicit projections, preview one typed change, and confirm the next encrypted inform is not a setparam. Apply with the token, verify the delivered full maps, wait for the matching version, restart the controller, send a fresh inform, and apply an unrelated change. Preserve unknown records and omitted values in both families. Keep injected emulator capabilities labeled synthetic.

```go
preview, err := client.PreviewSwitch(ctx, switchID, switchUpdate)
if err != nil {
    t.Fatal("live switch preview failed")
}
_, err = client.ApplySwitchPreview(ctx, switchID, switchUpdate, preview.Token)
if err != nil {
    t.Fatal("live switch apply failed")
}
```

Use the public client against the actual controller socket in the existing isolated live run; derive IDs from that run's adopted inventory.

- [ ] **Step 2: Run live adoption, preview, apply, and restart validation.**

```sh
UNIFI_LIVE_E2E=1 go test ./integration -run '^TestLiveAPSwitch$' -count=1 -v -timeout=15m
```

Expected: live AP and switch protocol tests pass, including signal cleanup. Preserve private captures and verified checksums. Report emulator protocol evidence separately from hardware behavior.

- [ ] **Step 3: Produce the physical legacy-network dry run.**

Inspect the currently active controller socket, registered AP, private desired configuration, full last submitted baseline, and fresh authenticated report. Resolve the legacy SSID from the explicit operator-selected private file, not list order. Create an owner-only request file that supplies only that network's BSS disable while preserving required resource identity. For full Apply's collection replacement semantics, retain all existing collection members, with peers carrying identities and omitted policy only. Use an owner-only script with private device/file variables; suppress raw bodies and parameter values from command logging.

```sh
unifi-go apply ap --device "$device_id" --file "$request_file" --dry-run
```

Save the returned opaque token in an owner-only file. Compare the private compiled candidate against the baseline and require that the only policy changes are the legacy network's bound BSS keys. Confirm state bytes, queue count, and reported version remain unchanged. Record anonymous counts and pass/fail only. Resolve current service paths and binary provenance from live evidence; do not reuse old physical run paths blindly.

- [ ] **Step 4: Apply and verify the already authorized legacy-network change.**

Apply the same request with the token against the intended active controller. Use session authorization for the legacy-network fix; do not re-request an already granted action. If physical application has not been authorized in the executing session, finish the dry-run evidence and obtain that authority before this step.

```sh
unifi-go apply ap --device "$device_id" --file "$request_file" --preview-token-file "$token_file"
```

Wait for the authenticated reported version to match the queued version. Verify each legacy-network authentication record reports/applies `bss_transition=disabled`, every peer retains its own prior value or absence, unrelated radio/security/VLAN policy remains unchanged, and existing virtual access points remain running. Use read-only device inspection if ordinary informs do not expose the BSS value. A matching version alone is insufficient. Keep passwords, SSID values, and physical identifiers private. Leave the intended legacy-network fix applied.

- [ ] **Step 5: Update operator instructions and evidence once.**

Document explicit baseline import, omission behavior, preview, and deliberate reconciliation in the README's existing how-to. Record actual socket, compiler, emulator, physical dry-run, and physical applied evidence separately in the evidence page. Do not claim client association or physical switch forwarding/PoE without those tests. Preserve private captures and original configuration evidence.

### Task 7: Verify the prerequisite and commit its completion record

**Files:** Use the source and tests above; keep raw logs and captures outside tracked documentation. Review every changed source path and the new specification.

**Interfaces:** Consumes Tasks 1 through 6. Produces a verified baseline/composition API ready for resource mutations.

- [ ] **Step 1: Run exact shared checks and the built result.**

```sh
make help
make fmt
make check
make test
go test -race ./...
make build
```

`make check` is the lint alias shown by current `make help`; it does not replace `make test`. Run the produced executable's help and a socket preview against the isolated controller. Record build exit status and actual executable path, then verify the executed artifact corresponds to this build. Do not rely only on timestamps.

- [ ] **Step 2: Verify fixture coverage and all acceptance evidence.**

```sh
go test ./integration -run '^(TestProfileFixtures|TestAPCompilerFromNetworkServerFixture|TestSwitchCompilerFromNetworkServerFixture)$' -count=1 -v
git fetch origin
git diff --check
```

Expected: all pass. Confirm migration, raw exactness, arbitrary commands, capability-only admission, unknown-policy preservation, BSS omission, preview immutability, token freshness, atomic failure, restart composition, and physical applied acceptance each have an observed result.

- [ ] **Step 3: Perform adversarial review and fix reproduced failures.**

Use the repository's adversarial-review playbook and strongest available review model for the user-visible, parsing, persistence, and concurrency changes. Attack duplicate and ambiguous baseline bindings, null/omission confusion, concurrent apply, save failure, stale raw ownership, removed-resource remapping, unsupported untouched settings, command JSON collisions, and output leakage. Re-run only affected checks after fixes, then the required shared gates. Record verified findings without claiming unrun hardware gates passed.

- [ ] **Step 4: Commit the prerequisite as logical signed slices and verify signatures.**

Use imperative commit subjects and the exact Codex trailer. Before any authorized push, fetch and inspect every commit in `origin/main..HEAD`; verify each signature and raw `gpgsig` header. Keep the original source checkout's unrelated files and old plan unchanged. Do not merge or deploy from a documentation approval alone.

### Task 8: Execute every task in the preserved generic resource plan

**Files:** Execute the exact file scope of the existing [Generic AP and Switch Resources Implementation Plan](/Users/agoodkind/Sites/unifi-go/docs/superpowers/plans/2026-09-07-generic-device-resources.md). Read the preserved source-checkout artifact because ignored plans are absent from this isolated worktree. Keep that original plan intact. Track completion and reconciliation evidence separately in its existing private progress and final-review artifacts.

**Interfaces:** Consume this prerequisite's presence-aware types, complete baseline, bindings, compiler input/result, atomic commit, preview, and pending state. Produce every public resource method and CLI operation required by the original four tasks. The new specification governs all contradictions.

- [ ] **Step 1: Complete old Task 1, stable radio and WiFi identities.**

Add `RadioID`, stable physical identity, repeated-band selectors, deep clones, and compiler integration coverage. Preserve `Optional` on policy and selector collections. Adapt `RadioIDs` to `Optional[[]RadioID]`. Match bindings by stable IDs and carry every unknown resource record through changed ordering. Keep the old capability and synthetic-index rejection tests.

- [ ] **Step 2: Complete old Task 2, atomic resource mutation.**

Implement all WiFi/radio/port mutations and safe list views. Reuse `compileLocked`, `commitCompiledLocked`, and awaiting state from Task 5 instead of introducing a second transaction. Enforce pending and drift guards. Clone the full baseline, projection, and bindings. `AddWiFi` copies complete source-owned records; `Set` preserves omitted fields; removal updates owned records and references only. Persist full composed bodies, overriding the old prohibition on compiled-body persistence.

```go
// Resource mutation is an overlay on the same authoritative baseline.
candidate, err := c.compileLocked(device, family, updatedAP, updatedSwitch)
if err != nil {
    return "", err
}
return c.commitCompiledLocked(device, candidate)
```

Inside the mutation transaction, compare the fresh report's version to desired version before this call. `updatedAP` and `updatedSwitch` are the family-specific request produced by the old plan's mutation callback; exactly one is nonnil. Do not feed a regenerated configuration that marks untouched policy as newly supplied.

- [ ] **Step 3: Complete old Task 3, public APIs and concise CLI.**

Implement every listed public method, socket operation, selector-file rule, safe WiFi view, and omitted-device uniqueness check. Preserve the existing BSS optional field in resource requests and copies. Update the old plan's Go literals to presence constructors in implementation, without changing the preserved plan. Prove all commands through its real socket integration and executable path.

- [ ] **Step 4: Complete old Task 4, live preservation and physical WiFi addition.**

Run all original emulator, physical, restart, capture, build, documentation, and final-review steps. Preserve the already applied legacy BSS disable while adding, setting, and removing WiFi resources. Reconcile the old full-generation and no-template expectations to this spec's explicit baseline contract. Keep its physical temporary-removal approval requirement unless the executing session already authorizes that exact operation. Missing physical evidence leaves this task incomplete.

- [ ] **Step 5: Run every remaining old-plan command and close every checkbox in the separate progress record.**

```sh
go test ./cmd/unifi-go -run '^TestTypedControlIntegration$' -count=1 -v
UNIFI_LIVE_E2E=1 go test ./integration -run '^TestLiveAPSwitch$' -count=1 -v -timeout=15m
make check
go test -race ./...
go test ./integration -run '^TestProfileFixtures$' -count=1 -v
docker build -t unifi-go-resource-check .
docker image inspect unifi-go-resource-check --format '{{.Id}}'
docker image rm unifi-go-resource-check
```

Expected: every command passes. Record the disposable image identity before removing that exact image tag. Preserve captures and run directories. Completion requires every old task and its acceptance criteria, including the physical addition and preserved BSS policy; finishing only the prerequisite does not finish this plan.
