package registry

import (
	acctmod "github.com/maestroi/hardener/internal/modules/accounting/acct"
	auditdmod "github.com/maestroi/hardener/internal/modules/accounting/auditd"
	bannermod "github.com/maestroi/hardener/internal/modules/banner"
	sysctlmod "github.com/maestroi/hardener/internal/modules/kernel/sysctl"
	logrotmod "github.com/maestroi/hardener/internal/modules/logging/logrotate"
	debsumsmod "github.com/maestroi/hardener/internal/modules/packages/debsums"
	unattmod "github.com/maestroi/hardener/internal/modules/packages/unattended"
	sshmod "github.com/maestroi/hardener/internal/modules/ssh"
)

// Default returns the production registry with all bundled modules registered.
func Default() *Registry {
	r := New()
	r.Register(sshmod.New())
	r.Register(debsumsmod.New())
	r.Register(unattmod.New())
	r.Register(bannermod.New())
	r.Register(logrotmod.New())
	r.Register(acctmod.New())
	r.Register(auditdmod.New())
	r.Register(sysctlmod.New())
	return r
}
