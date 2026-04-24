# cc-switch-router Migration

This project was previously named `portr-rs`.

## Scope of the rename

- Crate/binary name: `portr-rs` -> `cc-switch-router`
- Release asset: `portr-rs-linux-amd64` -> `cc-switch-router-linux-amd64`
- Default config dir: `~/.config/portr-rs/` -> `~/.config/cc-switch-router/`
- Preferred env prefix: `PORTR_RS_*` -> `CC_SWITCH_ROUTER_*`
- Preferred internal probe paths:
  - `/_portr/health` -> `/_share-router/health`
  - `/_portr/request-logs` -> `/_share-router/request-logs`
  - `/_portr/share-runtime` -> `/_share-router/share-runtime`
- Preferred internal headers:
  - `X-Portr-Probe` -> `X-Share-Router-Probe`
  - `X-Portr-Error` -> `X-Share-Router-Error`
  - `X-Portr-Error-Reason` -> `X-Share-Router-Error-Reason`

## Compatibility kept in this version

This version still accepts:

- legacy `PORTR_RS_*` environment variables
- legacy env file at `~/.config/portr-rs/.env`
- legacy DB path at `~/.config/portr-rs/portr-rs.db`
- legacy host key path at `~/.config/portr-rs/ssh_host_ed25519_key`
- legacy internal probe routes under `/_portr/*`
- legacy internal probe/error headers using `X-Portr-*`

This is intentional so existing deployments can upgrade without a hard cutover.

## Recommended deployment migration

1. Replace the binary with `cc-switch-router`.
2. Update systemd or process manager commands to the new binary path.
3. Move env vars from `PORTR_RS_*` to `CC_SWITCH_ROUTER_*`.
4. Move config files from `~/.config/portr-rs/` to `~/.config/cc-switch-router/`.
5. Keep the old files around until you confirm the new deployment is stable.

## Example systemd changes

Before:

```ini
EnvironmentFile=%h/.config/portr-rs/.env
ExecStart=/opt/portr-rs/portr-rs
```

After:

```ini
EnvironmentFile=%h/.config/cc-switch-router/.env
ExecStart=/opt/cc-switch-router/cc-switch-router
```

## Removal plan

Legacy compatibility should be removed only after all active desktop clients
and server deployments have been upgraded.
