# Controller record sync

unifi-go keeps a copy of the configuration a UniFi Network Application holds and
moves records in either direction on request. Nothing runs on a schedule and
nothing reconciles in the background; an operator starts each sync and reads the
difference it reports.

## Records stay generic

A controller record is a JSON object, and the sync carries it unchanged. No part
of the sync understands what a wireless network or a firewall rule means, so a
collection the controller gains needs one registry entry rather than a
translator. That is why the sync covers port profiles, firewall rules and groups,
port forwards, routes, RADIUS profiles, user groups, deep packet inspection
groups, hotspot records, site settings, client records, and devices, and not only
WiFi.

This is a different mechanism from the typed access point and switch
configuration unifi-go compiles into inform messages. Typed configuration
describes one device family and compiles to device records. The sync moves
controller records between a controller and a directory, and the two never read
each other's state.

## Identity survives the controller

The controller assigns each record an identifier that means nothing anywhere
else, so the sync keys records on what an operator named instead: the record name
for most collections, the setting key for a site setting, and the hardware
address for a device or a client. Matching on that identity is what lets a record
move between two controllers, and it is why two records sharing one name in a
collection stop the sync rather than guessing.

## A stored record carries intent, not counters

Most collections store whole. A device record and a client record mix
configuration with live counters that change on every inform, so those two
collections store only their configurable members. Without that, every pull would
rewrite the same files and a review diff would show traffic totals instead of
decisions.

The controller also assigns fields the operator never chooses, such as the record
identifier, the site identifier, and generated per-network keys. Those never
reach a stored file and never count as a difference.

## A write overlays, it does not replace

A push sends the controller's own record with the stored fields applied over it.
Editing one field therefore leaves every neighbouring field on that record alone,
including fields the sync does not manage. A create sends only the stored fields
and lets the controller assign the rest.

## Removal is opt in

Neither direction removes a destination record by default. A source that is
partial, stale, or filtered by a collection selection would otherwise delete live
configuration. Removal happens only when the operator asks for it, and the
controller still refuses to remove a device, a client, or a site setting through
this path.

## Secrets are stored but never printed

Rendered output replaces every credential member with a digest of its value, at
any depth inside a record, so a changed passphrase shows as a different digest
while the value stays out of the terminal and out of any log. A boolean beside a
credential name, such as whether a passphrase was generated, stays readable
because it carries no secret.

The stored files are a different matter. They hold the controller's real values,
including WiFi passphrases, the mesh key, and RADIUS secrets, because a push has
to send them back. They are written mode 0600 inside mode 0700 directories.

## Stored files stay stable

Each record becomes one file whose object members are sorted and indented the
same way every time, so a later pull rewrites a file only when the controller
actually changed. A file name percent-escapes every character outside letters,
digits, and `.`, `_`, and `-`, which is what keeps a hardware address or a
wireless name with a slash in it from colliding with another record or from
breaking on a file system that rejects those characters.

## What the sync does not do

Adoption stays with the controller. The sync never creates or removes a device,
because a device exists once the controller adopts it and disappears once the
controller forgets it.

The sync has no conflict detection. Two operators editing the same record on
opposite sides produce a last-writer-wins result, and the difference printed
before the write is the only warning.

Records that reference another record do so by the controller's own identifier.
A wireless network names its network configuration, its user group, and its
access point groups that way. Moving such a record to a second controller carries
identifiers that controller does not hold, so restoring onto the same controller
works while migrating between two controllers needs those references remapped
first.
