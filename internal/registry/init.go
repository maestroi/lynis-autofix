package registry

import (
	acctmod "github.com/maestroi/hardener/internal/modules/accounting/acct"
	auditdmod "github.com/maestroi/hardener/internal/modules/accounting/auditd"
	manualmod "github.com/maestroi/hardener/internal/modules/advisory/manual"
	pamfaillockmod "github.com/maestroi/hardener/internal/modules/auth/pamfaillock"
	pamhistmod "github.com/maestroi/hardener/internal/modules/auth/pamhistory"
	passagingmod "github.com/maestroi/hardener/internal/modules/auth/passwordaging"
	pwqualmod "github.com/maestroi/hardener/internal/modules/auth/pwquality"
	sudoersmod "github.com/maestroi/hardener/internal/modules/auth/sudoers"
	umaskmod "github.com/maestroi/hardener/internal/modules/auth/umask"
	bannermod "github.com/maestroi/hardener/internal/modules/banner"
	grubpasswdmod "github.com/maestroi/hardener/internal/modules/boot/grubpassword"
	grubpermsmod "github.com/maestroi/hardener/internal/modules/boot/grubperms"
	homemountmod "github.com/maestroi/hardener/internal/modules/filesystem/homemount"
	tmpmountmod "github.com/maestroi/hardener/internal/modules/filesystem/tmpmount"
	compilermod "github.com/maestroi/hardener/internal/modules/hardening/compiler"
	coredumpmod "github.com/maestroi/hardener/internal/modules/kernel/coredump"
	kernelmodsmod "github.com/maestroi/hardener/internal/modules/kernel/modules"
	protocolsmod "github.com/maestroi/hardener/internal/modules/kernel/protocols"
	sysctlmod "github.com/maestroi/hardener/internal/modules/kernel/sysctl"
	usbstoragemod "github.com/maestroi/hardener/internal/modules/kernel/usbstorage"
	logrotmod "github.com/maestroi/hardener/internal/modules/logging/logrotate"
	remotelogmod "github.com/maestroi/hardener/internal/modules/logging/remotelog"
	dnsmod "github.com/maestroi/hardener/internal/modules/network/dns"
	firewallmod "github.com/maestroi/hardener/internal/modules/network/firewall"
	aidemod "github.com/maestroi/hardener/internal/modules/packages/aide"
	aptconfigmod "github.com/maestroi/hardener/internal/modules/packages/aptconfig"
	debpurgemod "github.com/maestroi/hardener/internal/modules/packages/debpurge"
	debsecanmod "github.com/maestroi/hardener/internal/modules/packages/debsecan"
	debsumsmod "github.com/maestroi/hardener/internal/modules/packages/debsums"
	unattmod "github.com/maestroi/hardener/internal/modules/packages/unattended"
	sshmod "github.com/maestroi/hardener/internal/modules/ssh"
)

// Default returns the production registry with all bundled modules registered.
func Default() *Registry {
	r := New()
	r.Register(sshmod.New())
	r.Register(pwqualmod.New())
	r.Register(passagingmod.New())
	r.Register(umaskmod.New())
	r.Register(pamhistmod.New())
	r.Register(pamfaillockmod.New())
	r.Register(sudoersmod.New())
	r.Register(debsumsmod.New())
	r.Register(unattmod.New())
	r.Register(bannermod.New())
	r.Register(logrotmod.New())
	r.Register(acctmod.New())
	r.Register(auditdmod.New())
	r.Register(sysctlmod.New())
	r.Register(coredumpmod.New())
	// Batch 1: safe modules
	r.Register(aptconfigmod.New())
	r.Register(debpurgemod.New())
	r.Register(debsecanmod.New())
	r.Register(aidemod.New())
	r.Register(firewallmod.New())
	r.Register(grubpermsmod.New())
	r.Register(usbstoragemod.New())
	r.Register(protocolsmod.New())
	// Batch 2: medium modules
	r.Register(compilermod.New())
	r.Register(dnsmod.New())
	r.Register(remotelogmod.New())
	// Batch 3: dangerous modules
	r.Register(tmpmountmod.New())
	r.Register(homemountmod.New())
	r.Register(grubpasswdmod.New())
	r.Register(kernelmodsmod.New())
	// Advisory catch-all — must be last
	r.Register(manualmod.New())
	return r
}
