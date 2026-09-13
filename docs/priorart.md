# Prior Art

The proof of concept reuses current implementations and treats their claims as inputs
to reproduce against the physical testbed.

## Reused directly

- [jda/pixiedust](https://github.com/jda/pixiedust) at
  `a4356227df56ac74e77eba1ed8cdc703a483781d` reads packet captures, reassembles HTTP,
  follows inform encryption, extracts adoption keys, and prints decoded payloads.
  The local throwaway copy adds a wait-group and TCP assembler flush because the
  upstream command could exit before parser goroutines completed.
- [jamesbraid/unifi-emu](https://github.com/jamesbraid/unifi-emu) at
  `f8db1c229d09741d871702952e8de363982dae61` generated a synthetic `U7PG2` inform.
  Image `0.5` is pinned by index digest
  `sha256:86d2de638e5f105858a3534c9cc1459be877ce8ee2a799684e102e34bbda7ac0`.
- [mitmproxy](https://docs.mitmproxy.org/stable/concepts/modes/) 12.2.1 records the
  complete reverse-proxy flow on port `8080`. Its image index is pinned to
  `sha256:743b6cdc817211d64bc269f5defacca8d14e76e647fc474e5c7244dbcb645141`.
- [netshoot](https://github.com/nicolaka/netshoot) 0.14 supplies `tcpdump` inside the
  Network Server namespace. Its image index is pinned to
  `sha256:7f08c4aff13ff61a35d30e30c5c1ea8396eac6ab4ce19fd02d5a4b3b5d0d09a2`.
- [Wireshark](https://www.wireshark.org/docs/dfref/u/ubdp.html) supplies a second
  physical capture engine, HTTP reassembly, packet counts, and the Ubiquiti discovery
  dissector.

## Used as protocol evidence

- [unifi-gateway](https://github.com/amd989/unifi-gateway) provides active Python
  implementations of TNBU, AES-CBC, AES-GCM, zlib, Snappy, discovery, and controller
  provisioning.
- [OpenUniFi](https://github.com/dachsbaerli/OpenUniFi) documents working adoption
  and key-rotation behavior for emulated devices.
- [Reverse Engineered UniFi Protocol](https://github.com/fxkr/unifi-protocol-reverse-engineering)
  documents the TNBU header, port `8080` HTTP exchange, compression, and encryption.
- [The unofficial inform guide](https://jrjparks.github.io/unofficial-unifi-guide/protocols/inform.html)
  documents the default key, packet flags, AES modes, and compression order.
- [LinuxServer.io Network Application](https://github.com/linuxserver/docker-unifi-network-application)
  provides the Docker Network Server and external MongoDB contract.
- [Ubiquiti self-hosting guidance](https://help.ui.com/hc/en-us/articles/34210126298775-Self-Hosting-UniFi)
  states that UniFi OS Server requires host services and is not available as a
  standalone Docker or Podman container.

## Deliberately not reimplemented

The proof of concept does not create a new TNBU codec, crypto layer, AP payload model,
or packet reassembler. `pixiedust` owns offline packet interpretation, and
`unifi-emu` remains the preferred protocol package for the future Go implementation.
