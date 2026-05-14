# hardener

`hardener` is a Go CLI that reads Lynis findings and plans/applies safe remediations with rollback metadata.

## Current status

- Implemented and usable: `plan`, `apply`, `rollback`
- Stub commands (not implemented yet): `audit`, `report`

## Prerequisites

- Ubuntu host (project modules currently target Ubuntu)
- Go 1.22+
- Lynis report file available (default: `/var/log/lynis-report.dat`)
- Root privileges for real `apply`/`rollback` runs

## Build

```bash
go build -o hardener .
```

## Quick start

1) Generate a Lynis report:

```bash
sudo lynis audit system
```

2) Preview remediations (no changes):

```bash
sudo ./hardener plan --dry-run
```

3) Apply remediations:

```bash
sudo ./hardener apply
```

4) Apply non-interactively:

```bash
sudo ./hardener apply --yes
```

## Common usage

Plan only specific findings:

```bash
sudo ./hardener plan --dry-run --finding AUTH-9282 --finding PKGS-7370
```

Plan only specific modules:

```bash
sudo ./hardener plan --dry-run --module auth-sudoers-perms
```

Show plan as JSON:

```bash
sudo ./hardener plan --dry-run --output json
```

Allow dangerous actions in planning/apply:

```bash
sudo ./hardener plan --confirm-dangerous
sudo ./hardener apply --confirm-dangerous
```

Dry-run apply (executor simulation, no mutations):

```bash
sudo ./hardener apply --dry-run
```

Rollback:

```bash
sudo ./hardener rollback --list
sudo ./hardener rollback --run-id <RUN_ID>
```

Preview rollback only:

```bash
sudo ./hardener rollback --run-id <RUN_ID> --dry-run
```

## Configuration

Use `--config` to load `hardener.yaml`.

Example:

```yaml
version: "1"
profile: server
state_dir: /var/lib/hardener
confirm_dangerous: false
lynis:
  binary: /usr/sbin/lynis
  report_path: /var/log/lynis-report.dat
  log_path: /var/log/lynis.log
  extra_flags: []
```

Run with config:

```bash
sudo ./hardener plan --dry-run --config /path/to/hardener.yaml
```

## Profiles

Bundled profiles:

- `server` (default)
- `docker-host`
- `minimal`
- `validator-node.example`

Select a profile:

```bash
sudo ./hardener plan --dry-run --profile docker-host
```

## State and rollback data

- Default state dir: `/var/lib/hardener`
- Run metadata and rollback manifests are stored there
- Override with `--state-dir`

## Command help

```bash
./hardener --help
./hardener plan --help
./hardener apply --help
./hardener rollback --help
```

## Notes and limitations

- `plan --fresh` currently warns and reuses the existing report.
- `apply --audit` flag exists but is not implemented yet.
- `audit` and `report` commands are placeholders.
- `--profile` currently resolves bundled profile names.
