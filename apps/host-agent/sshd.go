package main

// The SSH server check (ADR 0037, addendum "SSH server"): which SSH server the host has, the C library it is built against, the
// OpenSSH package version, and the global values of a few authentication settings from /etc/ssh/sshd_config and the files it
// includes. Only files are read, as the unprivileged agent user: no sshd is run (`sshd -T` needs root and the host keys), no
// ldd, and /etc/shadow is never opened (it is not readable for the agent anyway). A file that cannot be read is named, not guessed.

import (
	"debug/elf"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const (
	// MaxSSHConfigFiles is how many configuration files are read at most (sshd_config and what it includes).
	MaxSSHConfigFiles = 32
	// MaxSSHConfigBytes is the largest configuration file read.
	MaxSSHConfigBytes = 256 * 1024
	// maxSSHIncludeDepth is sshd's own limit for nested Include directives.
	maxSSHIncludeDepth = 16
	// maxSSHMatchValues is how many distinct values of one setting in Match blocks are reported.
	maxSSHMatchValues = 8
	// maxELFBytes bounds the binaries whose ELF headers are read (sshd is a few MB).
	maxELFBytes = 64 << 20
)

// SSHSetting is the effective global value of one setting, whether it is OpenSSH's default (not set in any file), and the distinct
// values Match blocks set for it.
type SSHSetting struct {
	Value   string   `json:"value"`
	Default bool     `json:"default"`
	Match   []string `json:"match"`
}

// SSHSettings are the settings GarnetOps judges.
type SSHSettings struct {
	PasswordAuthentication       SSHSetting `json:"passwordAuthentication"`
	KbdInteractiveAuthentication SSHSetting `json:"kbdInteractiveAuthentication"`
	PermitRootLogin              SSHSetting `json:"permitRootLogin"`
	UsePAM                       SSHSetting `json:"usePam"`
	PermitEmptyPasswords         SSHSetting `json:"permitEmptyPasswords"`
	PubkeyAuthentication         SSHSetting `json:"pubkeyAuthentication"`
}

// SSHSkipped is a configuration file that was not read, and why: "unreadable", "too-large", "not-regular", "outside" (not under
// /etc/ssh), "limit" (more than MaxSSHConfigFiles files), "depth" (Include nested too deep) or "host-key" (ssh_host_*, never
// opened even where an Include's glob matches it).
type SSHSkipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// SSHConfig is what the configuration files say. Read is false when sshd_config itself could not be read (Problem says why);
// then there are no settings, because defaults would be a guess.
type SSHConfig struct {
	Read     bool         `json:"read"`
	Problem  string       `json:"problem,omitempty"`
	Files    []string     `json:"files"`
	Skipped  []SSHSkipped `json:"skipped"`
	Settings *SSHSettings `json:"settings"`
	// global holds every global value read, also those not reported (Kerberos, GSSAPI), for choosing the program.
	global map[string]string
}

// SSHPackage is the installed package of the SSH server.
type SSHPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SSHFacts is the optional inventory field `sshd`.
type SSHFacts struct {
	// Server is "openssh" (/usr/sbin/sshd), "dropbear" or "none".
	Server  string      `json:"server"`
	Package *SSHPackage `json:"package"`
	// Libc is "musl", "glibc" or "unknown": from the program interpreter of sshd, else from the loaders the system has.
	Libc string `json:"libc"`
	// Program is the SSH server program the host starts: /usr/sbin/sshd, or on Alpine (OpenRC) /usr/sbin/sshd.pam or
	// /usr/sbin/sshd.krb5, chosen the way Alpine's /etc/init.d/sshd chooses it.
	Program string `json:"program"`
	// PamLinked says whether that program or its sshd-session and sshd-auth helpers are linked against libpam (nil: not known).
	// Without it, UsePAM has no effect.
	PamLinked *bool      `json:"pamLinked"`
	Config    *SSHConfig `json:"config"`
}

const sshdPath = "/usr/sbin/sshd"

// sshDefaults are OpenSSH's own (upstream) defaults. A distribution may build OpenSSH with other defaults; GarnetOps only reads
// files and says so.
var sshDefaults = map[string]string{
	"passwordauthentication":       "yes",
	"kbdinteractiveauthentication": "yes",
	"permitrootlogin":              "prohibit-password",
	"usepam":                       "no",
	"permitemptypasswords":         "no",
	"pubkeyauthentication":         "yes",
}

// sshKeyword maps the keywords GarnetOps reads (case-insensitive) to one name; ChallengeResponseAuthentication is the old name of
// KbdInteractiveAuthentication and the same setting for sshd, so the first of either counts.
func sshKeyword(word string) string {
	switch k := strings.ToLower(word); k {
	case "challengeresponseauthentication":
		return "kbdinteractiveauthentication"
	case "passwordauthentication", "kbdinteractiveauthentication", "permitrootlogin", "usepam", "permitemptypasswords",
		"pubkeyauthentication", "kerberosauthentication", "gssapiauthentication":
		return k
	}
	return ""
}

func isRegular(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular()
}

// ReadSSHFacts looks at the host's SSH server. It never fails: what cannot be read is reported as unknown.
func ReadSSHFacts(root string, packages []Package) *SSHFacts {
	facts := &SSHFacts{Server: "none", Libc: "unknown"}
	switch {
	// Alpine's openssh-server-pam brings only sshd.pam (and sshd.krb5 its own); /usr/sbin/sshd comes with openssh-server.
	case isRegular(hostPath(root, sshdPath)) || isRegular(hostPath(root, sshdPath+".pam")) ||
		isRegular(hostPath(root, sshdPath+".krb5")):
		facts.Server = "openssh"
	case isRegular(hostPath(root, "/usr/sbin/dropbear")) || isRegular(hostPath(root, "/usr/bin/dropbear")):
		facts.Server = "dropbear"
	}
	interp := ""
	if facts.Server == "openssh" {
		facts.Config = ReadSSHConfig(root)
		facts.Program = sshdProgram(root, facts.Config)
		interp, facts.PamLinked = sshdLinkage(root, facts.Program)
		names := []string{"openssh-server", "openssh-server-pam", "openssh-server-krb5", "openssh"}
		if flavor := sshdFlavor(facts.Program); flavor != "" {
			// The package of the program that runs comes first; all of them carry the same OpenSSH version.
			names = append([]string{"openssh-server-" + flavor[1:]}, names...)
		}
		facts.Package = sshPackage(packages, names...)
	} else if facts.Server == "dropbear" {
		facts.Package = sshPackage(packages, "dropbear")
	}
	facts.Libc = DetectLibc(root, interp)
	return facts
}

// sshdProgram says which SSH server program the host starts. Debian, Ubuntu, Fedora and their kin have one, /usr/sbin/sshd.
// Alpine builds three, and its OpenRC script (/etc/init.d/sshd) picks one at every start: SSHD_BINARY from /etc/conf.d/sshd
// if set; else sshd.krb5 if installed and the configuration switches on Kerberos or GSSAPI; else sshd.pam if installed and the
// configuration says UsePAM yes; else sshd. The script asks the program itself (sshd -G); the agent runs nothing and reads the
// same files, first value wins.
func sshdProgram(root string, cfg *SSHConfig) string {
	if DetectServiceManager(root) != "openrc" {
		return sshdPath
	}
	if binary := openrcSSHDBinary(root); binary != "" {
		return binary
	}
	if cfg == nil || cfg.global == nil {
		return sshdPath
	}
	executable := func(p string) bool {
		info, err := os.Stat(hostPath(root, p))
		return err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0
	}
	g := cfg.global
	if executable(sshdPath+".krb5") && (g["kerberosauthentication"] == "yes" || g["gssapiauthentication"] == "yes") {
		return sshdPath + ".krb5"
	}
	if executable(sshdPath+".pam") && g["usepam"] == "yes" {
		return sshdPath + ".pam"
	}
	return sshdPath
}

// openrcSSHDBinary reads SSHD_BINARY from /etc/conf.d/sshd: the last plain assignment of an absolute path. A value the shell would
// still expand ($, backquotes) is not guessed at.
func openrcSSHDBinary(root string) string {
	file := hostPath(root, "/etc/conf.d/sshd")
	if !isRegular(file) {
		// Not a FIFO or device, whose opening could block the report.
		return ""
	}
	text, err := readLimited(file, 64*1024)
	if err != nil {
		return ""
	}
	found := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		value, ok := strings.CutPrefix(line, "SSHD_BINARY=")
		if !ok {
			continue
		}
		if i := strings.Index(value, " #"); i >= 0 {
			value = value[:i]
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if value == "" || strings.ContainsAny(value, "$`\\ \t") || !strings.HasPrefix(value, "/") || len(value) > 200 {
			found = ""
			continue
		}
		found = path.Clean(value)
	}
	return found
}

// sshdFlavor is the suffix of one of Alpine's server programs (".pam", ".krb5"), or "" for plain sshd and anything else.
func sshdFlavor(program string) string {
	switch base := path.Base(program); base {
	case "sshd.pam", "sshd.krb5":
		return strings.TrimPrefix(base, "sshd")
	}
	return ""
}

// sshdLinkage reads the program interpreter of the server program and whether PAM is linked. Since OpenSSH 9.8 and 10.0 the
// session and the authentication run in helper programs (sshd-session, sshd-auth) that link libpam where sshd itself may not;
// on Alpine they carry the program's suffix (sshd-auth.pam). PAM counts as linked when any of them links it; nil when none could
// be read.
func sshdLinkage(root, program string) (string, *bool) {
	flavor := sshdFlavor(program)
	files := []string{program}
	for _, dir := range []string{"/usr/lib/ssh", "/usr/lib/openssh", "/usr/libexec/openssh", "/usr/libexec"} {
		files = append(files, dir+"/sshd-session"+flavor, dir+"/sshd-auth"+flavor)
	}
	interp := ""
	var pam *bool
	for _, file := range files {
		full := hostPath(root, file)
		if !isRegular(full) {
			continue
		}
		i, linked := elfFacts(full)
		if interp == "" {
			interp = i
		}
		if linked != nil {
			if pam == nil {
				pam = new(bool)
			}
			*pam = *pam || *linked
		}
	}
	return interp, pam
}

func sshPackage(packages []Package, names ...string) *SSHPackage {
	for _, name := range names {
		for _, p := range packages {
			if p.Name == name {
				return &SSHPackage{Name: p.Name, Version: p.Version}
			}
		}
	}
	return nil
}

// elfFacts reads the program interpreter of a binary (/lib/ld-musl-x86_64.so.1, /lib64/ld-linux-x86-64.so.2) and whether it is
// linked against libpam. Only the ELF headers are read; nothing is run. Empty and nil when the file cannot be read.
func elfFacts(file string) (interp string, pam *bool) {
	defer func() {
		// debug/elf on a damaged file must not stop the report.
		if recover() != nil {
			interp, pam = "", nil
		}
	}()
	f, err := os.Open(file)
	if err != nil {
		return "", nil
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || info.Size() > maxELFBytes {
		return "", nil
	}
	e, err := elf.NewFile(f)
	if err != nil {
		return "", nil
	}
	for _, prog := range e.Progs {
		if prog.Type == elf.PT_INTERP {
			data, _ := io.ReadAll(io.LimitReader(prog.Open(), 256))
			interp = strings.TrimRight(string(data), "\x00")
			break
		}
	}
	if libs, err := e.ImportedLibraries(); err == nil {
		linked := false
		for _, lib := range libs {
			if strings.HasPrefix(lib, "libpam.so") {
				linked = true
			}
		}
		pam = &linked
	}
	return interp, pam
}

// DetectLibc says which C library the SSH server uses: from its program interpreter when known, otherwise from the dynamic
// loaders the system has. A glibc system may carry musl's loader too (Debian's musl package), so the loaders decide only when
// exactly one kind is present.
func DetectLibc(root, interp string) string {
	switch base := path.Base(interp); {
	case strings.HasPrefix(base, "ld-musl-"):
		return "musl"
	case strings.HasPrefix(base, "ld-linux"):
		return "glibc"
	}
	musl := anyGlob(root, "/lib/ld-musl-*.so.1", "/usr/lib/ld-musl-*.so.1")
	glibc := anyGlob(root, "/lib/ld-linux*.so.*", "/lib64/ld-linux*.so.*", "/usr/lib/ld-linux*.so.*", "/usr/lib64/ld-linux*.so.*")
	switch {
	case musl && !glibc:
		return "musl"
	case glibc && !musl:
		return "glibc"
	}
	return "unknown"
}

func anyGlob(root string, patterns ...string) bool {
	for _, pattern := range patterns {
		if found, _ := filepath.Glob(hostPath(root, pattern)); len(found) > 0 {
			return true
		}
	}
	return false
}

type sshParser struct {
	root, etcSSH string
	files        []string
	skipped      []SSHSkipped
	global       map[string]string
	match        map[string][]string
}

// ReadSSHConfig reads /etc/ssh/sshd_config and the files it includes, the way sshd reads them for its global settings: the first
// value of a setting outside Match blocks wins; values inside Match blocks apply only to some connections and are reported apart.
// An Include inside a Match block belongs to that block; a Match block inside an included file ends with that file.
func ReadSSHConfig(root string) *SSHConfig {
	p := &sshParser{root: root, global: map[string]string{}, match: map[string][]string{}}
	cfg := &SSHConfig{Files: []string{}, Skipped: []SSHSkipped{}}
	etcSSH, err := filepath.EvalSymlinks(hostPath(root, "/etc/ssh"))
	if err != nil {
		cfg.Problem = "missing"
		return cfg
	}
	p.etcSSH = etcSSH
	main := "/etc/ssh/sshd_config"
	text, reason := p.read(main)
	if reason != "" {
		cfg.Problem = reason
		if errors.Is(statErr(hostPath(root, main)), os.ErrNotExist) {
			cfg.Problem = "missing"
		}
		return cfg
	}
	p.files = append(p.files, main)
	p.parse(text, false, 0)
	cfg.Read = true
	cfg.global = p.global
	// Append keeps what the initial empty slices hold: a nil slice would be sent as null, and the server's schema expects a list.
	cfg.Files = append(cfg.Files, p.files...)
	cfg.Skipped = append(cfg.Skipped, p.skipped...)
	setting := func(key string) SSHSetting {
		s := SSHSetting{Value: p.global[key], Match: p.match[key]}
		if s.Match == nil {
			s.Match = []string{}
		}
		if s.Value == "" {
			s.Value, s.Default = sshDefaults[key], true
		}
		return s
	}
	cfg.Settings = &SSHSettings{
		PasswordAuthentication:       setting("passwordauthentication"),
		KbdInteractiveAuthentication: setting("kbdinteractiveauthentication"),
		PermitRootLogin:              setting("permitrootlogin"),
		UsePAM:                       setting("usepam"),
		PermitEmptyPasswords:         setting("permitemptypasswords"),
		PubkeyAuthentication:         setting("pubkeyauthentication"),
	}
	return cfg
}

func statErr(p string) error {
	_, err := os.Stat(p)
	return err
}

// read returns a configuration file's text, or why it was not read. name is the path on the host (under /etc/ssh).
func (p *sshParser) read(name string) (string, string) {
	full := hostPath(p.root, name)
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", "unreadable"
	}
	if resolved != p.etcSSH && !strings.HasPrefix(resolved, p.etcSSH+string(filepath.Separator)) {
		return "", "outside"
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", "unreadable"
	}
	if !info.Mode().IsRegular() {
		return "", "not-regular"
	}
	if info.Size() > MaxSSHConfigBytes {
		return "", "too-large"
	}
	f, err := os.Open(resolved)
	if err != nil {
		return "", "unreadable"
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxSSHConfigBytes+1))
	if err != nil {
		return "", "unreadable"
	}
	if len(data) > MaxSSHConfigBytes {
		return "", "too-large"
	}
	return string(data), ""
}

func (p *sshParser) skip(name, reason string) {
	if len(p.skipped) < MaxSSHConfigFiles {
		p.skipped = append(p.skipped, SSHSkipped{Path: name, Reason: reason})
	}
}

// parse reads one file's lines. inMatch is whether the file was included inside a Match block.
func (p *sshParser) parse(text string, inMatch bool, depth int) {
	for _, line := range strings.Split(text, "\n") {
		keyword, args := splitSSHLine(line)
		if keyword == "" {
			continue
		}
		switch strings.ToLower(keyword) {
		case "match":
			// "Match all" ends a Match block as far as the following lines are concerned.
			inMatch = !(len(args) == 1 && strings.EqualFold(args[0], "all"))
			continue
		case "include":
			p.include(args, inMatch, depth)
			continue
		}
		key := sshKeyword(keyword)
		if key == "" || len(args) == 0 {
			continue
		}
		value := strings.ToLower(args[0])
		if len(value) > 40 {
			value = value[:40]
		}
		if inMatch {
			if !slices.Contains(p.match[key], value) && len(p.match[key]) < maxSSHMatchValues {
				p.match[key] = append(p.match[key], value)
			}
		} else if _, set := p.global[key]; !set {
			p.global[key] = value
		}
	}
}

func (p *sshParser) include(patterns []string, inMatch bool, depth int) {
	for _, pattern := range patterns {
		if !strings.HasPrefix(pattern, "/") {
			// sshd takes relative paths from /etc/ssh.
			pattern = "/etc/ssh/" + pattern
		}
		pattern = path.Clean(pattern)
		if pattern != "/etc/ssh" && !strings.HasPrefix(pattern, "/etc/ssh/") {
			p.skip(pattern, "outside")
			continue
		}
		matches, err := filepath.Glob(hostPath(p.root, pattern))
		if err != nil {
			p.skip(pattern, "unreadable")
			continue
		}
		sort.Strings(matches)
		for _, full := range matches {
			name := "/" + strings.TrimPrefix(filepath.ToSlash(strings.TrimPrefix(full, filepath.Clean(p.root))), "/")
			if depth+1 > maxSSHIncludeDepth {
				p.skip(name, "depth")
				continue
			}
			if strings.HasPrefix(path.Base(name), "ssh_host_") {
				// A host key (or its public half) matched by a wide glob: never opened.
				p.skip(name, "host-key")
				continue
			}
			if len(p.files) >= MaxSSHConfigFiles {
				p.skip(name, "limit")
				continue
			}
			text, reason := p.read(name)
			if reason != "" {
				p.skip(name, reason)
				continue
			}
			p.files = append(p.files, name)
			// The included file starts in the including line's Match state; its own Match blocks end with it.
			p.parse(text, inMatch, depth+1)
		}
	}
}

// splitSSHLine splits a configuration line into its keyword and arguments as sshd does: the keyword ends at white space or '=',
// arguments are separated by white space and may be double-quoted, and an argument starting with '#' starts a comment.
func splitSSHLine(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil
	}
	end := strings.IndexAny(line, " \t=")
	if end < 0 {
		return line, nil
	}
	keyword := line[:end]
	rest := strings.TrimLeft(line[end:], " \t")
	rest = strings.TrimLeft(strings.TrimPrefix(rest, "="), " \t")
	var args []string
	for rest != "" {
		if strings.HasPrefix(rest, "#") {
			break
		}
		var arg string
		if strings.HasPrefix(rest, `"`) {
			closing := strings.Index(rest[1:], `"`)
			if closing < 0 {
				break // an unterminated quote: sshd refuses the line
			}
			arg, rest = rest[1:1+closing], rest[2+closing:]
		} else {
			stop := strings.IndexAny(rest, " \t")
			if stop < 0 {
				stop = len(rest)
			}
			arg, rest = rest[:stop], rest[stop:]
		}
		args = append(args, arg)
		rest = strings.TrimLeft(rest, " \t")
	}
	return keyword, args
}
