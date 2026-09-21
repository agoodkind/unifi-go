# Run a UniFi OS Server lab

The lab instance is the Lima guest `unifi-os`. The guest disk is `/Volumes/Chaos Storage/Lima/unifi-os`.

```sh
export LIMA_HOME='/Volumes/Chaos Storage/Lima'
limactl start unifi-os
```

Open the UniFi OS UI at `https://<Mac LAN IPv4>:11443`. Device informs use `http://<Mac LAN IPv4>:8080/inform` after the Docker Network Application releases that port.

`--controller-url` is an origin such as `https://<Mac LAN IPv4>:11443`. `unifiapi.Dial` still posts `/api/login` and does not prefix `/proxy/network`.