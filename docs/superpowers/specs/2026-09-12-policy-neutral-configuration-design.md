# Policy-neutral configuration design

Typed configuration changes preserve the full persisted device configuration and change only policy the operator supplies.

This is the authoritative contract for the prerequisite implementation and the subsequent generic AP and switch resources work. It is a target design, not a claim that the current implementation satisfies it.

## Define the boundary

The transport owns adoption, device identity, keys, encryption, persistent state, command queues, and arbitrary command delivery. It does not select wireless security, roaming, management services, filtering, time zones, VLANs, radio behavior, or switch policy.

Profiles translate operator settings into model or family-specific key mappings and enforce evidenced capability constraints. Profiles may encode mandatory relationships between records, such as an interface reference required by a selected VLAN. A profile cannot choose an optional policy because a captured reference reply happened to contain it. A reproduced model or firmware exception changes a mapping or constraint, never device admission.

Operator input selects policy. The persisted full configuration supplies unspecified values. Ordinary informs supply observations and capability evidence, not missing configuration or credentials. A baseline import is an explicit operator action, not automatic co-management with another controller.

Support exactly APs and switches. Gateways remain excluded.

Do not add a model admission allowlist, fixed radio count, fixed port count, or fixed PoE layout.

## Preserve one full baseline

Each device has one authoritative, versioned baseline containing complete management and system configuration text. Typed desired resources and stable wire bindings accompany that baseline as its projection, not a second independent source of configuration. Every successful typed apply atomically persists the resulting baseline, projection, bindings, and desired version before queueing its complete reply.

Compilation clones the baseline, resolves the requested resource identities, overlays supplied values, updates only required dependent records, and preserves every other key and value. Unknown keys survive. Unknown records attached to a known resource follow that resource when indexes change. Removal deletes only the selected resource's owned records and references that become unused. Ambiguous ownership fails before persistence or queueing; the compiler never deletes an entire unknown namespace to make regeneration simpler.

Stable bindings associate WiFi networks with all their per-radio wireless, authentication, interface, and bridge records. Radios bind to reported physical interfaces and switches to physical port indexes. Names and indexes from an array position are insufficient when several resources could match. Persist bindings so restarting or reordering a request cannot retarget a setting.

An imported baseline may contain policy outside the typed API. A typed request can change another supported field without validating or normalizing the untouched policy. New resources require explicit policy or an explicitly selected source resource. A newly added WiFi network can copy its source's untyped records as well as typed fields; copying does not activate a compiled-in template.

The baseline holds configuration secrets because complete device replies already contain them. Keep state and temporary state files owner-readable and owner-writable only. Never emit configuration bodies, passwords, password hashes, credential paths, device identifiers, or secret-derived comparison digests in public previews or test logs. Existing identity-returning device APIs retain their contract; new acceptance summaries use anonymous resource counts.

## Distinguish omission from policy

Typed policy fields represent three states: omitted, supplied, and explicit null where clearing is supported. Omission preserves the persisted value, including an absent key. Explicit false, zero where valid, an empty collection, or a disabled enum is a supplied choice. Explicit null clears only a documented nullable field. Null on a nonnullable field is an error.

Keep the public `ApplyAP` and `ApplySwitch` method names and signatures. Make their configuration fields presence-aware while retaining their JSON names and plain value shapes. Existing Go callers must use the presence constructor for supplied values. Existing serialized configurations keep their supplied values. No migration inserts an omitted value.

WiFi names, radio selectors, and port indexes remain resource identities. Policy fields, nested policy objects, and top-level collections carry presence. A supplied top-level resource collection replaces its typed resource membership; an omitted collection preserves it. Within a retained resource, omitted policy preserves its baseline. An empty supplied collection deliberately removes its typed members, not unknown unrelated device records.

For VLAN and channel, explicit null selects untagged operation or automatic channel selection respectively. Omission preserves the current choice. A supplied SSH object changes its supplied credential fields; omission preserves existing SSH configuration. The initial nullable surface excludes disabling SSH through null. An unsupported explicit clear fails rather than silently inventing a meaning.

Full Apply remains the deliberate typed reconciliation path after reported drift. It replaces explicitly supplied collections and policies against the chosen baseline. Exact wholesale replacement remains available through raw `ApplyConfig`. Neither operation invents unspecified policy.

## Keep BSS Transition explicit

BSS Transition is the WiFi roaming feature controlled by `bss_transition`. Retain and complete the existing uncommitted `BSSTransitionMode`, `BSSTransitionEnabled`, `BSSTransitionDisabled`, validation, and per-network compiler changes. Their current fallback to `enabled` violates this contract.

The operator can set `bss_transition` to `disabled` for only the legacy SSID, which is a WiFi network name. Update every authentication record bound to that network. Other SSIDs retain their own baseline values independently. An omitted BSS field must never default to enabled. If the baseline lacks the key, omission leaves it absent. If a new resource or protocol requires an explicit choice, return a missing-policy error instead of guessing.

A later unrelated typed apply, a raw-baseline reconciliation, and a controller restart must not restore a hardcoded BSS value. Focused compiler coverage and the real controller socket flow prove all three states. Physical acceptance requires a dry run followed by verification of the applied legacy-network setting and unchanged peer networks. These checks expose no passwords or physical identifiers.

## Keep raw delivery exact

Raw `Client.ApplyConfig` preserves the caller's version and management and system text exactly. It does not parse, sort, normalize, augment, validate against a profile, restrict key names, require a model, or reinterpret security. Retain existing UTF-8 and JSON transport integrity checks. Encoding checks do not authorize policy checks.

Raw delivery remains usable for duplicate records or syntax the typed parser cannot represent. Persist the exact raw request as the latest baseline and last submitted configuration in the same atomic write. Invalidate the prior typed projection and bindings, because the raw payload may have replaced any of their records. Do not silently leave stale typed desired state eligible for mutation.

A later typed call requires explicit reconciliation when raw delivery invalidated ownership. Reconciliation parses an operator-selected complete baseline and re-establishes resource bindings without sending a command. Parse failure leaves raw delivery usable and returns a safe baseline error only from the typed path. A partial raw body is not proof of a complete typed baseline; the operator supplies the missing full namespace during reconciliation.

Arbitrary commands pass through a public command envelope with a command name and JSON parameters. Validate transport structure and reserved envelope collisions, not a command-name allowlist. Preserve the existing adoption command's required key and URI checks. Imperative commands remain volatile and do not replace the configuration baseline.

## Separate metadata from policy

Typed delivery may update adoption and routing metadata required to maintain this controller's connection. Isolate those exact fields and prove their necessity from the existing transport tests. Compute the desired version from the final policy content after overlay, using the existing exclusion of transient connection fields.

Remove implicit SSH activation, telemetry choices, crash-reporting choices, time-zone selection, filtering, roaming, rate settings, and service defaults from controller augmentation and blanket compiler defaults. Preserve corresponding baseline values unless the operator explicitly supplies a supported setting. An existing adoption workflow that installs generated SSH credentials must become an explicit operator option; adoption and baseline provisioning cannot silently enable SSH.

The raw path never receives this typed metadata augmentation.

## Migrate without sending configuration

Read existing state arrays, including the legacy `config` alias already accepted by the loader. Keep keys, adoption state, SSH records, typed desired data, desired version, and exact `LastSetParam` bodies. Loading does not enqueue or replay anything.

When a usable `LastSetParam` exists, derive the versioned baseline from its exact bodies. Preserve old explicit policy and unknown records. Reconstruct bindings only when the stored typed projection and complete payload identify resources uniquely and their versions agree. A later raw `LastSetParam` with a different version must invalidate older typed ownership.

When state lacks complete bodies or has ambiguous bindings, keep transport operational and return `baseline_required` or `baseline_unusable` from typed preview and apply. Do not regenerate the old full configuration to fabricate a baseline. An explicit baseline import establishes complete bodies and optional typed projections. It sends no command and does not claim the device applied that baseline.

Migration becomes durable through the normal atomic state writer on the next successful state transaction. A persistence failure restores prior in-memory state and leaves the queue unchanged. New state uses a schema version inside the optional baseline record so legacy arrays remain readable.

Queues and awaiting versions remain in memory. Restart clears them and requires a fresh authenticated inform before a typed mutation. A mismatching reported version then rejects incremental changes as drift. Full typed reconciliation remains deliberate, and raw delivery remains unrestricted by these typed guards.

## Preview the actual transaction

Provide `PreviewAP` and `PreviewSwitch` through the public client and real controller socket. The CLI exposes them through `apply ap --dry-run` and `apply switch --dry-run`. Preview executes the same resolution, baseline overlay, capability checks, secret reads, and version calculation as apply. It performs no state write, migration write, queue update, or awaiting update.

Return counts of added, changed, and removed records, an opaque expiring preview token, and safe errors. Keep bodies and secret-derived versions private. Applying with a preview token verifies that baseline revision, relevant report capabilities, operator request, and resolved secret contents still match the preview. An expired or stale token fails without mutation. A normal Apply without a token retains its supported interface.

A physical dry run verifies only compilation and absence of side effects. Applied acceptance additionally requires a matching authenticated reported version, decoded delivered records, unchanged unrelated records, the legacy network's applied BSS setting, and running virtual access points. Client association, switch forwarding, and electrical PoE remain separate claims.

## Reconcile the subsequent resource plan

Keep the existing [generic AP and switch resources plan](/Users/agoodkind/Sites/unifi-go/docs/superpowers/plans/2026-09-07-generic-device-resources.md) intact and execute every task after the prerequisite implementation passes. Read that preserved source-checkout artifact; it is ignored and absent from this isolated worktree. Its resource APIs, stable identities, pending and drift guards, device selection rules, live tests, and physical preservation gates remain required.

This specification supersedes the old complete-generation and no-template assumptions. The resource transaction compiles a full reply by overlaying the persisted full baseline. It does not generate every policy from typed fields. Explicitly importing a baseline is permitted; ordinary reports still do not reconstruct complete configuration.

This specification also supersedes the prohibition on persisting compiled bodies. Full bodies are required to preserve policy outside the typed projection. The existing full Apply recovery semantics now mean replacing supplied typed policy against that baseline. A resource `Set` preserves omitted policy in the selected resource, and `AddWiFi` copies its complete bound source records.

Implement the resource plan's pending and drift guards once in the shared transaction. Reuse them when the subsequent plan reaches its mutation task. Preserve its requirements for atomic failure, safe views, stable identities, no pending replay, and no force option. Apply the presence-aware types to its example structs and deep clones. No superseded assumption permits skipping a resource task or its acceptance evidence.
