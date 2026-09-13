# Throwaway capture proof of concept

This proof of concept records the physical link twice, inserts mitmproxy before the
Network Server, records the container link, copies controller logs, archives the
controller volumes, and runs `pixiedust` after capture.

Run:

```bash
./poc/setup_prior_art.zsh
./poc/start.zsh
```

Wait for `ARMED` before resetting the access point. Stop from another terminal:

```bash
./poc/stop.zsh
```

If the capture process died before cleanup, run:

```bash
./poc/recover.zsh
```

Verify the stopped run with its printed directory:

```bash
./poc/verify.zsh /absolute/run/directory
```

Runs contain keys, credentials, topology, and client data. Keep them local.
