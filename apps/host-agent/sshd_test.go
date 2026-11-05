package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFile(t *testing.T, root, name, text string) {
	t.Helper()
	full := hostPath(root, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSplitSSHLine(t *testing.T) {
	cases := []struct {
		line    string
		keyword string
		args    []string
	}{
		{"  PasswordAuthentication no", "PasswordAuthentication", []string{"no"}},
		{"PermitRootLogin=yes", "PermitRootLogin", []string{"yes"}},
		{"UsePAM = yes # a comment", "UsePAM", []string{"yes"}},
		{"\tInclude \"/etc/ssh/a b.conf\" other.conf", "Include", []string{"/etc/ssh/a b.conf", "other.conf"}},
		{"# PasswordAuthentication no", "", nil},
		{"", "", nil},
		{"Match User backup Address 192.0.2.0/24", "Match", []string{"User", "backup", "Address", "192.0.2.0/24"}},
	}
	for _, c := range cases {
		keyword, args := splitSSHLine(c.line)
		if keyword != c.keyword || !reflect.DeepEqual(args, c.args) {
			t.Errorf("%q: got %q %q", c.line, keyword, args)
		}
	}
}

// sshd takes the first value of a global setting, from sshd_config and its includes in order; Match blocks only for some
// connections. Includes are relative to /etc/ssh and globbed in lexical order.
func TestSSHConfigFirstMatchWinsWithIncludeAndMatch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/ssh/sshd_config", strings.Join([]string{
		"# Debian-style: the drop-ins first, so they win",
		"Include /etc/ssh/sshd_config.d/*.conf",
		"PasswordAuthentication yes",
		"permitrootlogin=yes",
		"ChallengeResponseAuthentication no",
		"KbdInteractiveAuthentication yes",
		"UsePAM yes",
		"Match User backup",
		"  PasswordAuthentication yes",
		"  PermitRootLogin no",
		"  Include match.d/*.conf",
		"Match all",
		"PermitEmptyPasswords yes",
		"Match Address 192.0.2.0/24",
		"  PermitRootLogin yes",
		"",
	}, "\n"))
	writeFile(t, root, "/etc/ssh/sshd_config.d/10-hardening.conf", "PasswordAuthentication no\n")
	// A Match block inside an included file ends with that file.
	writeFile(t, root, "/etc/ssh/sshd_config.d/20-match.conf", "Match Group admins\n PubkeyAuthentication no\n")
	writeFile(t, root, "/etc/ssh/sshd_config.d/30-later.conf", "PasswordAuthentication yes\nPubkeyAuthentication yes\n")
	writeFile(t, root, "/etc/ssh/match.d/permit.conf", "PermitEmptyPasswords no\n")
	writeFile(t, root, "/etc/ssh/sshd_config.d/ignored.txt", "PasswordAuthentication yes\n")

	cfg := ReadSSHConfig(root)
	if !cfg.Read || cfg.Settings == nil {
		t.Fatalf("not read: %+v", cfg)
	}
	s := cfg.Settings
	check := func(name string, got SSHSetting, value string, isDefault bool, match []string) {
		t.Helper()
		if got.Value != value || got.Default != isDefault || !reflect.DeepEqual(got.Match, match) {
			t.Errorf("%s: got %+v, want %s default=%v match=%v", name, got, value, isDefault, match)
		}
	}
	check("PasswordAuthentication", s.PasswordAuthentication, "no", false, []string{"yes"})
	check("PermitRootLogin", s.PermitRootLogin, "yes", false, []string{"no", "yes"})
	// ChallengeResponseAuthentication is the same setting; it came first.
	check("KbdInteractiveAuthentication", s.KbdInteractiveAuthentication, "no", false, []string{})
	check("UsePAM", s.UsePAM, "yes", false, []string{})
	// After "Match all" the lines are global again; the Match-only include set "no" for one block only.
	check("PermitEmptyPasswords", s.PermitEmptyPasswords, "yes", false, []string{"no"})
	// 20-match.conf's Match block did not leak into 30-later.conf.
	check("PubkeyAuthentication", s.PubkeyAuthentication, "yes", false, []string{"no"})
	want := []string{
		"/etc/ssh/sshd_config",
		"/etc/ssh/sshd_config.d/10-hardening.conf",
		"/etc/ssh/sshd_config.d/20-match.conf",
		"/etc/ssh/sshd_config.d/30-later.conf",
		"/etc/ssh/match.d/permit.conf",
	}
	if !reflect.DeepEqual(cfg.Files, want) {
		t.Errorf("files: %v", cfg.Files)
	}
}

func TestSSHConfigDefaults(t *testing.T) {
	root := t.TempDir()
	// Alpine's shipped file: everything commented out.
	writeFile(t, root, "/etc/ssh/sshd_config", "#PermitRootLogin prohibit-password\n#PasswordAuthentication yes\nSubsystem sftp internal-sftp\n")
	cfg := ReadSSHConfig(root)
	s := cfg.Settings
	if s == nil {
		t.Fatalf("no settings: %+v", cfg)
	}
	got := map[string]SSHSetting{
		"passwordauthentication":       s.PasswordAuthentication,
		"kbdinteractiveauthentication": s.KbdInteractiveAuthentication,
		"permitrootlogin":              s.PermitRootLogin,
		"usepam":                       s.UsePAM,
		"permitemptypasswords":         s.PermitEmptyPasswords,
		"pubkeyauthentication":         s.PubkeyAuthentication,
	}
	for key, setting := range got {
		if setting.Value != sshDefaults[key] || !setting.Default {
			t.Errorf("%s: got %+v", key, setting)
		}
	}
	if s.PasswordAuthentication.Value != "yes" || s.PermitRootLogin.Value != "prohibit-password" || s.UsePAM.Value != "no" {
		t.Errorf("upstream defaults changed: %+v", s)
	}
}

// The server's schema expects lists; a nil slice would be sent as null, and the whole sshd field would be dropped.
func TestSSHConfigJSONHasListsNotNull(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/ssh/sshd_config", "PasswordAuthentication no\n")
	for _, cfg := range []*SSHConfig{ReadSSHConfig(root), ReadSSHConfig(t.TempDir())} {
		out, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "null") && !strings.Contains(string(out), `"settings":null`) {
			t.Errorf("a list is null: %s", out)
		}
		if !strings.Contains(string(out), `"files":[`) || !strings.Contains(string(out), `"skipped":[]`) {
			t.Errorf("files or skipped missing: %s", out)
		}
	}
}

func TestSSHConfigUnreadableOrMissing(t *testing.T) {
	if got := ReadSSHConfig(t.TempDir()); got.Read || got.Problem != "missing" || got.Settings != nil {
		t.Errorf("no /etc/ssh: %+v", got)
	}
	root := t.TempDir()
	if err := os.MkdirAll(hostPath(root, "/etc/ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := ReadSSHConfig(root); got.Read || got.Problem != "missing" {
		t.Errorf("no sshd_config: %+v", got)
	}
	// A configuration that is not a regular file is not read, and no defaults are claimed for it.
	if err := os.MkdirAll(hostPath(root, "/etc/ssh/sshd_config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := ReadSSHConfig(root); got.Read || got.Problem != "not-regular" || got.Settings != nil {
		t.Errorf("a directory: %+v", got)
	}
	if os.Geteuid() != 0 {
		unreadable := t.TempDir()
		writeFile(t, unreadable, "/etc/ssh/sshd_config", "PasswordAuthentication no\n")
		if err := os.Chmod(hostPath(unreadable, "/etc/ssh/sshd_config"), 0o000); err != nil {
			t.Fatal(err)
		}
		if got := ReadSSHConfig(unreadable); got.Read || got.Problem != "unreadable" {
			t.Errorf("mode 0600 of another user: %+v", got)
		}
	}
}

// Only regular files under /etc/ssh, at most 32 of them and 256 KiB each; everything else is named as skipped.
func TestSSHConfigBounds(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, outside, "/secret.conf", "PasswordAuthentication yes\n")
	writeFile(t, root, "/etc/ssh/sshd_config", strings.Join([]string{
		"Include /etc/ssh/a/*.conf",
		"Include /etc/passwd ../shadow",
		"Include big.conf link.conf dir.conf",
		"Include many/*.conf",
		"Include /etc/ssh/*",
		"PasswordAuthentication no",
	}, "\n"))
	writeFile(t, root, "/etc/ssh/ssh_host_ed25519_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nPasswordAuthentication yes\n")
	writeFile(t, root, "/etc/ssh/big.conf", "PasswordAuthentication yes\n"+strings.Repeat("#", MaxSSHConfigBytes))
	if err := os.Symlink(hostPath(outside, "/secret.conf"), hostPath(root, "/etc/ssh/link.conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(hostPath(root, "/etc/ssh/dir.conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		writeFile(t, root, fmt.Sprintf("/etc/ssh/many/%02d.conf", i), "PubkeyAuthentication no\n")
	}
	cfg := ReadSSHConfig(root)
	if !cfg.Read || cfg.Settings.PasswordAuthentication.Value != "no" {
		t.Fatalf("got %+v", cfg)
	}
	if len(cfg.Files) != MaxSSHConfigFiles {
		t.Errorf("read %d files", len(cfg.Files))
	}
	reasons := map[string]string{}
	for _, s := range cfg.Skipped {
		if _, seen := reasons[s.Path]; !seen {
			reasons[s.Path] = s.Reason
		}
	}
	for path, reason := range map[string]string{
		"/etc/passwd":                   "outside",
		"/etc/shadow":                   "outside",
		"/etc/ssh/big.conf":             "too-large",
		"/etc/ssh/link.conf":            "outside",
		"/etc/ssh/dir.conf":             "not-regular",
		"/etc/ssh/many/39.conf":         "limit",
		"/etc/ssh/ssh_host_ed25519_key": "host-key",
	} {
		if reasons[path] != reason {
			t.Errorf("%s: got %q, want %q (all: %v)", path, reasons[path], reason, cfg.Skipped)
		}
	}
	if len(cfg.Skipped) > MaxSSHConfigFiles {
		t.Errorf("skipped list not bounded: %d", len(cfg.Skipped))
	}
}

func TestSSHConfigIncludeLoopStops(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/ssh/sshd_config", "Include sshd_config\nPasswordAuthentication no\n")
	cfg := ReadSSHConfig(root)
	if !cfg.Read || len(cfg.Files) > MaxSSHConfigFiles || cfg.Settings.PasswordAuthentication.Value != "no" {
		t.Fatalf("got %d files, %+v", len(cfg.Files), cfg.Settings)
	}
}

func TestDetectLibcFromLoaders(t *testing.T) {
	alpine := t.TempDir()
	writeFile(t, alpine, "/lib/ld-musl-x86_64.so.1", "")
	if got := DetectLibc(alpine, ""); got != "musl" {
		t.Errorf("alpine: %q", got)
	}
	debian := t.TempDir()
	writeFile(t, debian, "/lib64/ld-linux-x86-64.so.2", "")
	if got := DetectLibc(debian, ""); got != "glibc" {
		t.Errorf("debian: %q", got)
	}
	// Debian with its musl package: both loaders, so only sshd's own interpreter could tell.
	both := t.TempDir()
	writeFile(t, both, "/lib64/ld-linux-x86-64.so.2", "")
	writeFile(t, both, "/lib/ld-musl-x86_64.so.1", "")
	if got := DetectLibc(both, ""); got != "unknown" {
		t.Errorf("both: %q", got)
	}
	if got := DetectLibc(both, "/lib/ld-musl-aarch64.so.1"); got != "musl" {
		t.Errorf("interpreter musl: %q", got)
	}
	if got := DetectLibc(alpine, "/lib64/ld-linux-x86-64.so.2"); got != "glibc" {
		t.Errorf("interpreter glibc: %q", got)
	}
}

// A real dynamically linked program of this machine stands in for sshd: its interpreter decides the C library, even where a
// stray musl loader exists.
func TestSSHFactsFromAnELFBinary(t *testing.T) {
	ls, err := exec.LookPath("ls")
	if err != nil {
		t.Skip("no ls")
	}
	interp, pam := elfFacts(ls)
	if interp == "" || pam == nil {
		t.Skipf("ls is not a dynamically linked ELF program here (%q)", interp)
	}
	data, err := os.ReadFile(ls)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeFile(t, root, "/usr/sbin/sshd", string(data))
	writeFile(t, root, "/lib/ld-musl-x86_64.so.1", "")
	writeFile(t, root, "/etc/ssh/sshd_config", "PasswordAuthentication no\n")
	facts := ReadSSHFacts(root, []Package{{Name: "openssh-client", Version: "1:9.2p1-2+deb12u3"}, {Name: "openssh-server", Version: "1:9.2p1-2+deb12u3"}})
	want := DetectLibc(t.TempDir(), interp)
	if facts.Server != "openssh" || facts.Libc != want || facts.PamLinked == nil || *facts.PamLinked {
		t.Errorf("got %+v (interpreter %s)", facts, interp)
	}
	if facts.Package == nil || facts.Package.Name != "openssh-server" {
		t.Errorf("package: %+v", facts.Package)
	}
	// Not an ELF file at all: nothing claimed.
	if interp, pam := elfFacts(hostPath(root, "/etc/ssh/sshd_config")); interp != "" || pam != nil {
		t.Errorf("text file: %q %v", interp, pam)
	}
}

// An Alpine host: apk's database, musl, OpenSSH without PAM, Alpine's commented-out configuration. The inventory field is what the
// server's schema (sshdFactsSchema in @garnetops/core/agent) reads.
func TestSSHFactsOnAlpine(t *testing.T) {
	root := t.TempDir()
	alpine := OSRelease{ID: "alpine", VersionID: "3.22.2", PrettyName: "Alpine Linux v3.22"}
	writeFile(t, root, "/lib/apk/db/installed", "P:musl\nV:1.2.5-r10\nA:x86_64\no:musl\n\n"+
		"P:openssh-server\nV:10.0_p1-r9\nA:x86_64\no:openssh\n\nP:openssh-client-default\nV:10.0_p1-r9\nA:x86_64\no:openssh\n")
	writeFile(t, root, "/lib/ld-musl-x86_64.so.1", "")
	writeFile(t, root, "/usr/sbin/sshd", "not an ELF file in this test")
	writeFile(t, root, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n#PasswordAuthentication yes\nAllowTcpForwarding no\n")
	if err := os.MkdirAll(hostPath(root, "/run/openrc"), 0o755); err != nil {
		t.Fatal(err)
	}
	packages, err := ReadPackages(root, alpine)
	if err != nil || len(packages) != 3 || packages[1].Purl != "pkg:apk/alpine/openssh-server@10.0_p1-r9?arch=x86_64&upstream=openssh&distro=alpine-3.22.2" {
		t.Fatalf("got %+v %v", packages, err)
	}
	facts := ReadSSHFacts(root, packages)
	data, _ := json.Marshal(facts)
	got := string(data)
	for _, part := range []string{
		`"server":"openssh"`,
		`"package":{"name":"openssh-server","version":"10.0_p1-r9"}`,
		`"libc":"musl"`,
		`"pamLinked":null`,
		`"read":true`,
		`"passwordAuthentication":{"value":"yes","default":true,"match":[]}`,
		`"usePam":{"value":"no","default":true,"match":[]}`,
	} {
		if !strings.Contains(got, part) {
			t.Errorf("missing %s in %s", part, got)
		}
	}
	if DetectServiceManager(root) != "openrc" {
		t.Error("OpenRC not seen")
	}
}

// A program linked against libpam (su, login or passwd) and one without it (ls) stand in for the server programs.
func pamStandIns(t *testing.T) (withPAM, without []byte) {
	t.Helper()
	for _, name := range []string{"su", "login", "passwd"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if _, pam := elfFacts(p); pam != nil && *pam {
			withPAM, _ = os.ReadFile(p)
			break
		}
	}
	if ls, err := exec.LookPath("ls"); err == nil {
		if _, pam := elfFacts(ls); pam != nil && !*pam {
			without, _ = os.ReadFile(ls)
		}
	}
	if withPAM == nil || without == nil {
		t.Skip("no dynamically linked programs with and without libpam here")
	}
	return withPAM, without
}

func writeExecutable(t *testing.T, root, name string, data []byte) {
	t.Helper()
	writeFile(t, root, name, string(data))
	if err := os.Chmod(hostPath(root, name), 0o755); err != nil {
		t.Fatal(err)
	}
}

// Alpine's three server programs: OpenRC starts sshd.pam when it is installed and the configuration says UsePAM yes (and
// sshd.krb5 for Kerberos or GSSAPI), else sshd; SSHD_BINARY in /etc/conf.d/sshd overrides that. PAM is linked in the helpers.
func TestSSHProgramOnAlpine(t *testing.T) {
	withPAM, without := pamStandIns(t)
	alpine := func(config string) string {
		root := t.TempDir()
		if err := os.MkdirAll(hostPath(root, "/run/openrc"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeExecutable(t, root, "/usr/sbin/sshd", without)
		writeExecutable(t, root, "/usr/lib/ssh/sshd-session", without)
		writeExecutable(t, root, "/usr/lib/ssh/sshd-auth", without)
		writeExecutable(t, root, "/usr/sbin/sshd.pam", without)
		writeExecutable(t, root, "/usr/lib/ssh/sshd-session.pam", withPAM)
		writeExecutable(t, root, "/usr/lib/ssh/sshd-auth.pam", withPAM)
		writeFile(t, root, "/etc/ssh/sshd_config", config)
		return root
	}
	packages := []Package{{Name: "openssh-server-pam", Version: "10.0_p1-r9"}, {Name: "openssh-server", Version: "10.0_p1-r9"}}
	check := func(name string, f *SSHFacts, program string, pam bool, pkg string) {
		t.Helper()
		if f.Program != program || f.PamLinked == nil || *f.PamLinked != pam || f.Package == nil || f.Package.Name != pkg {
			t.Errorf("%s: got program %q pam %v package %+v", name, f.Program, f.PamLinked, f.Package)
		}
	}

	root := alpine("Include /etc/ssh/sshd_config.d/*.conf\n")
	writeFile(t, root, "/etc/ssh/sshd_config.d/pam.conf", "usepam YES\n")
	check("UsePAM yes", ReadSSHFacts(root, packages), "/usr/sbin/sshd.pam", true, "openssh-server-pam")

	root = alpine("#UsePAM yes\nMatch User backup\n  UsePAM yes\n")
	check("UsePAM only in a Match block", ReadSSHFacts(root, packages), "/usr/sbin/sshd", false, "openssh-server")

	root = alpine("UsePAM yes\n")
	if err := os.Chmod(hostPath(root, "/usr/sbin/sshd.pam"), 0o644); err != nil {
		t.Fatal(err)
	}
	check("sshd.pam not executable", ReadSSHFacts(root, packages), "/usr/sbin/sshd", false, "openssh-server")

	root = alpine("UsePAM no\n")
	writeFile(t, root, "/etc/conf.d/sshd", "# SSHD_BINARY=/usr/sbin/sshd\nexport SSHD_BINARY=\"/usr/sbin/sshd.pam\"  # with PAM\n")
	check("SSHD_BINARY", ReadSSHFacts(root, packages), "/usr/sbin/sshd.pam", true, "openssh-server-pam")
	writeFile(t, root, "/etc/conf.d/sshd", "SSHD_BINARY=/usr/sbin/sshd.pam\nSSHD_BINARY=\"$PREFIX/sshd\"\n")
	check("SSHD_BINARY the agent cannot expand", ReadSSHFacts(root, packages), "/usr/sbin/sshd", false, "openssh-server")

	root = alpine("GSSAPIAuthentication yes\nUsePAM yes\n")
	writeExecutable(t, root, "/usr/sbin/sshd.krb5", without)
	writeExecutable(t, root, "/usr/lib/ssh/sshd-auth.krb5", withPAM)
	check("Kerberos", ReadSSHFacts(root, packages), "/usr/sbin/sshd.krb5", true, "openssh-server")

	// Only the PAM flavour installed (no openssh-server): still an OpenSSH server.
	root = alpine("UsePAM yes\n")
	if err := os.Remove(hostPath(root, "/usr/sbin/sshd")); err != nil {
		t.Fatal(err)
	}
	f := ReadSSHFacts(root, packages[:1])
	check("only openssh-server-pam", f, "/usr/sbin/sshd.pam", true, "openssh-server-pam")
	if f.Server != "openssh" {
		t.Errorf("server: %q", f.Server)
	}

	// Without OpenRC (a systemd host) the program is sshd, whatever else lies around.
	root = alpine("UsePAM yes\n")
	if err := os.Remove(hostPath(root, "/run/openrc")); err != nil {
		t.Fatal(err)
	}
	check("systemd", ReadSSHFacts(root, packages), "/usr/sbin/sshd", false, "openssh-server")
}

// OpenSSH 10 on Debian: sshd itself does not link libpam, sshd-session and sshd-auth in /usr/lib/openssh do.
func TestSSHPAMInTheHelpers(t *testing.T) {
	withPAM, without := pamStandIns(t)
	root := t.TempDir()
	writeExecutable(t, root, "/usr/sbin/sshd", without)
	writeExecutable(t, root, "/usr/lib/openssh/sshd-auth", withPAM)
	writeFile(t, root, "/etc/ssh/sshd_config", "UsePAM yes\n")
	f := ReadSSHFacts(root, []Package{{Name: "openssh-server", Version: "1:10.0p1-7"}})
	if f.Program != "/usr/sbin/sshd" || f.PamLinked == nil || !*f.PamLinked {
		t.Errorf("got %q %v", f.Program, f.PamLinked)
	}
}

func TestSSHFactsWithoutOpenSSH(t *testing.T) {
	none := t.TempDir()
	if f := ReadSSHFacts(none, nil); f.Server != "none" || f.Config != nil || f.Package != nil {
		t.Errorf("got %+v", f)
	}
	dropbear := t.TempDir()
	writeFile(t, dropbear, "/usr/sbin/dropbear", "")
	f := ReadSSHFacts(dropbear, []Package{{Name: "dropbear", Version: "2024.86-r0"}})
	if f.Server != "dropbear" || f.Config != nil || f.Package == nil || f.Package.Version != "2024.86-r0" {
		t.Errorf("got %+v", f)
	}
}

func TestDetectServiceManager(t *testing.T) {
	if got := DetectServiceManager(t.TempDir()); got != "" {
		t.Errorf("got %q", got)
	}
	systemd := t.TempDir()
	if err := os.MkdirAll(hostPath(systemd, "/run/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := DetectServiceManager(systemd); got != "systemd" {
		t.Errorf("got %q", got)
	}
}
