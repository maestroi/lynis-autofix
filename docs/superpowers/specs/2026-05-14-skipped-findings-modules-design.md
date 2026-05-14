# Design: Skipped Findings Modules (Batches 1–3)

**Date:** 2026-05-14  
**Status:** Approved  

## Problem

19 Lynis findings are currently skipped. 2 of them (`AUTH-9282`, `PKGS-7370`) skip correctly because the system is already compliant. The other 17 are routed to `advisory/manual` which emits "manual review required" for all of them — no automation is attempted.

## Goal

Implement automated remediation modules for all 17 remaining findings, grouped into 3 risk-tiered batches. Risky actions gate behind the existing `Dangerous: true` / `--confirm-dangerous` mechanism. Two config-dependent findings skip with a helpful profile hint rather than failing.

---

## Module Map

### Batch 1 — Safe (RiskLow / RiskMedium, `Dangerous: false`)

| Module path | Finding(s) | What it does |
|---|---|---|
| `internal/modules/packages/aptconfig/` | DEB-0280, DEB-0880 | Write APT periodic security config to `/etc/apt/apt.conf.d/99-hardener` |
| `internal/modules/packages/debpurge/` | DEB-0810 | Purge removed-but-not-purged packages (`dpkg --purge`) |
| `internal/modules/packages/debsecan/` | DEB-0811 | Install `debsecan` package |
| `internal/modules/packages/aide/` | FINT-4350 | Install `aide` and initialise its database (`aideinit`) |
| `internal/modules/network/firewall/` | FIRE-4513 | Install + enable UFW with `default deny incoming` |
| `internal/modules/boot/grubperms/` | BOOT-5264 | `chmod 600 /boot/grub/grub.cfg` |
| `internal/modules/kernel/usbstorage/` | USB-1000, HRDN-7230 | Write `/etc/modprobe.d/usb-storage.conf` blacklisting `usb-storage` |
| `internal/modules/kernel/protocols/` | NETW-3200 | Write `/etc/modprobe.d/disable-protocols.conf` blacklisting `dccp`, `sctp`, `rds`, `tipc` |

### Batch 2 — Medium (RiskMedium, `Dangerous: false`)

| Module path | Finding(s) | What it does |
|---|---|---|
| `internal/modules/hardening/compiler/` | HRDN-7222 | Remove world-execute bit from `gcc`, `cc`, `make` compiler tools |
| `internal/modules/network/dns/` | NAME-4028 | Enable `DNSSEC=yes` in `/etc/systemd/resolved.conf` |
| `internal/modules/logging/remotelog/` | LOGG-2190 | Configure rsyslog remote target — skips with hint if `remote_syslog_server` absent from profile |

### Batch 3 — Dangerous (`Dangerous: true`, requires `--confirm-dangerous`, RiskHigh/RiskCritical)

| Module path | Finding(s) | Risk | What it does |
|---|---|---|---|
| `internal/modules/filesystem/tmpmount/` | FILE-6310 | RiskHigh | Add `nodev,nosuid,noexec` to `/tmp` entry in `/etc/fstab` |
| `internal/modules/filesystem/homemount/` | FILE-7524 | RiskHigh | Add `nodev` to `/home` entry in `/etc/fstab` |
| `internal/modules/boot/grubpassword/` | BOOT-5122 | RiskCritical | Write GRUB password hash — skips with hint if `grub_password_hash` absent from profile |
| `internal/modules/kernel/modules/` | KRNL-5830 | RiskCritical | Write `/etc/sysctl.d/99-hardener-modules.conf` setting `kernel.modules_disabled=1` |

---

## Architecture

All 15 modules implement the existing stateless `modules.Module` interface. No new abstractions are introduced.

### Module lifecycle

1. **`Plan()`** — read-only inspection via `executor.Inspector`. Returns `Applicable: false` with a descriptive `SkipReason` when:
   - The system is already compliant (idempotent check)
   - Required profile config is missing (`grub_password_hash`, `remote_syslog_server`)
   Returns a full `PlannedAction` with `Steps`, `Risk`, `CanRollback`, and `Dangerous: true` (Batch 3 only) otherwise.

2. **`Apply()`** — executes the planned steps via `executor.Executor`. Wraps errors as `fmt.Errorf("module-id: action: %w", err)`.

3. **`Validate()`** — confirms desired end state (file content/perms, package installed, service active).

4. **`Rollback()`** — restores backed-up files via `RollbackFile` entries. Package installs use the existing no-op pattern (no removal to avoid dependency surprises).

### Profile additions

Two fields added to `model.Profile`:

```go
GrubPasswordHash   string `yaml:"grub_password_hash"   json:"grub_password_hash"`
RemoteSyslogServer string `yaml:"remote_syslog_server"  json:"remote_syslog_server"`
```

When absent, the relevant module's `Plan()` returns:
```
SkipReason: "set grub_password_hash in profile to enable BOOT-5122 remediation"
SkipReason: "set remote_syslog_server in profile to enable LOGG-2190 remediation"
```

### Advisory/manual cleanup

Once all 15 modules are registered in `internal/registry/init.go`, their finding IDs are removed from `advisory/manual/module.go`'s `supportedFindings` slice so they no longer emit "manual review required".

---

## Error Handling

- `Plan()` returns `(nil, error)` only for unexpected I/O failures (e.g., cannot read fstab). "Already compliant" and "missing config" are not errors.
- Batch 3 fstab modules back up the original `/etc/fstab` as a `RollbackFile` entry before writing.
- `kernel/modules/` backs up or creates a removal entry for `99-hardener-modules.conf`.

---

## Testing

Each module has a `module_test.go` using `testhelpers.FakeInspector` / `testhelpers.FakeExecutor`. No new test infrastructure.

Each module covers:

| Test case | Assertion |
|---|---|
| Already compliant | `Plan()` returns `Applicable: false` |
| Happy path | `Plan()` returns applicable action; `Apply()` succeeds; `Validate()` passes |
| Missing profile config | `Plan()` returns `Applicable: false` with hint in `SkipReason` (remotelog, grubpassword only) |
| Dangerous flag | `PlannedAction.Dangerous == true` (Batch 3 only) |

---

## Delivery Order

1. **Batch 1** — implement and ship all 8 safe modules + registry wiring + advisory cleanup for those findings
2. **Batch 2** — implement 3 medium modules + registry wiring + advisory cleanup  
3. **Batch 3** — implement 4 dangerous modules + profile fields + registry wiring + full advisory cleanup
