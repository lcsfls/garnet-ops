package main

// What the host's apt lists offer for its installed packages (Debian, Ubuntu): read from /var/lib/apt/lists, which apt keeps
// world-readable, so the agent stays unprivileged and read-only and makes no network request for it. GarnetOps turns these facts
// into "patchable now", "waiting for the mirror" and so on per finding (packages/core/src/apt.ts). Only what matters is sent: the
// sources with their Release fields, and the installed packages for which a source offers a newer version or which come from a
// source outside the distribution. Never the lists themselves.

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Bounds of what the agent reads and sends (the server checks the same limits: aptFactsSchema in @garnetops/core/agent).
const (
	MaxAptSources      = 200
	MaxAptPackages     = 5000
	MaxAptOffers       = 8
	maxAptIndexFiles   = 400
	maxAptReleaseBytes = 64 * 1024
	maxAptIndexBytes   = 512 << 20
	maxAptLineBytes    = 1 << 20
)

// AptSource is one source as the list file names show it, with what its Release file says.
type AptSource struct {
	ID         int      `json:"id"`
	Host       string   `json:"host"`
	Path       string   `json:"path"`
	Suite      string   `json:"suite"`
	Components []string `json:"components"`
	Origin     *string  `json:"origin"`
	Label      *string  `json:"label"`
	Codename   *string  `json:"codename"`
	Date       *string  `json:"date"`
	FetchedAt  *string  `json:"fetchedAt"`
	prefix     string
}

// AptOffer is the newest version one source offers for a package.
type AptOffer struct {
	Source  int    `json:"source"`
	Version string `json:"version"`
}

// AptPackage is an installed package the lists have something to say about.
type AptPackage struct {
	Name      string     `json:"name"`
	Arch      string     `json:"arch"`
	Installed string     `json:"installed"`
	From      []int      `json:"from"`
	Offers    []AptOffer `json:"offers"`
}

// AptFacts is the `apt` field of the inventory.
type AptFacts struct {
	ListsUpdatedAt *string      `json:"listsUpdatedAt"`
	Arch           *string      `json:"arch"`
	Sources        []AptSource  `json:"sources"`
	Packages       []AptPackage `json:"packages"`
}

var aptHost = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$`)

// decodeListName turns a part of a list file name back into a URL path: apt writes "/" as "_" and escapes "_" itself as "%5f".
func decodeListName(part string) string {
	path := strings.ReplaceAll(part, "_", "/")
	if decoded, err := url.PathUnescape(path); err == nil {
		return decoded
	}
	return path
}

// ParseListName splits the name of a Release file ("mirror.example.lan_ubuntu_dists_noble-security_InRelease") into host, path
// and suite. ok is false for any name that does not have that shape.
func ParseListName(name string) (host, path, suite, prefix string, ok bool) {
	var base string
	switch {
	case strings.HasSuffix(name, "_InRelease"):
		base = strings.TrimSuffix(name, "_InRelease")
	case strings.HasSuffix(name, "_Release"):
		base = strings.TrimSuffix(name, "_Release")
	default:
		return "", "", "", "", false
	}
	at := strings.LastIndex(base, "_dists_")
	if at <= 0 {
		return "", "", "", "", false
	}
	location, suiteEnc := base[:at], base[at+len("_dists_"):]
	host, pathEnc, _ := strings.Cut(location, "_")
	if !aptHost.MatchString(host) || suiteEnc == "" {
		return "", "", "", "", false
	}
	return strings.ToLower(host), decodeListName(pathEnc), decodeListName(suiteEnc), base + "_", true
}

// ParseReleaseFields reads the single-line fields of a Release or InRelease file (the signature armour is skipped) up to the first
// file list.
func ParseReleaseFields(text string) map[string]string {
	fields := map[string]string{}
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && strings.HasPrefix(lines[0], "-----BEGIN PGP SIGNED MESSAGE-----") {
		// The armour header ("Hash: SHA512") ends at the first empty line.
		for len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
			lines = lines[1:]
		}
	}
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "-----BEGIN PGP SIGNATURE-----") {
			break
		}
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			// "MD5Sum:", "SHA256:": the file list follows; nothing after it is needed.
			if strings.HasPrefix(key, "MD5") || strings.HasPrefix(key, "SHA") {
				break
			}
			continue
		}
		if _, seen := fields[key]; !seen {
			fields[key] = value
		}
	}
	return fields
}

// releaseDate reads the `Date:` of a Release file, as RFC 3339.
func releaseDate(value string) *string {
	for _, layout := range []string{time.RFC1123, time.RFC1123Z, "Mon, 2 Jan 2006 15:04:05 MST", "Mon, 2 Jan 2006 15:04:05 -0700"} {
		if t, err := time.Parse(layout, value); err == nil {
			s := t.UTC().Format(time.RFC3339)
			return &s
		}
	}
	return nil
}

func rfc3339(t time.Time) *string {
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// isDistributionOrigin mirrors isDistributionSource in @garnetops/core/apt: Origin "Ubuntu" or "Debian", or, without an Origin,
// an official host.
func isDistributionOrigin(s *AptSource) bool {
	if s.Origin != nil {
		o := strings.ToLower(strings.TrimSpace(*s.Origin))
		return o == "ubuntu" || o == "debian"
	}
	switch s.Host {
	case "archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com", "deb.debian.org", "security.debian.org":
		return true
	}
	return strings.HasSuffix(s.Host, ".archive.ubuntu.com")
}

func cleanField(value string, limit int) *string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len(value) > limit {
		value = value[:limit]
	}
	return optional(value)
}

type installedKey struct{ name, arch string }

type aptOffers struct {
	pkg    *Package
	from   map[int]bool
	offers map[int]string
}

// ReadAptFacts reads the apt lists of a host whose packages dpkg lists. It returns nil without apt lists. A list that cannot be read
// or does not parse is skipped; the work stops at the deadline with what it has.
func ReadAptFacts(root string, installed []Package, deadline time.Time) (*AptFacts, error) {
	dir := hostPath(root, "/var/lib/apt/lists")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Sources, from their Release files (InRelease wins over Release for the same suite).
	byPrefix := map[string]*AptSource{}
	var prefixes []string
	var newest time.Time
	for _, entry := range entries {
		host, path, suite, prefix, ok := ParseListName(entry.Name())
		if !ok || !entry.Type().IsRegular() {
			continue
		}
		if existing := byPrefix[prefix]; existing != nil && strings.HasSuffix(entry.Name(), "_Release") {
			continue
		}
		if _, known := byPrefix[prefix]; !known && len(byPrefix) >= MaxAptSources {
			continue
		}
		full := filepath.Join(dir, entry.Name())
		text, err := readLimited(full, maxAptReleaseBytes)
		if err != nil {
			continue
		}
		fields := ParseReleaseFields(text)
		source := &AptSource{
			Host:       host,
			Path:       path,
			Suite:      suite,
			Components: []string{},
			Origin:     cleanField(fields["Origin"], 100),
			Label:      cleanField(fields["Label"], 100),
			Codename:   cleanField(fields["Codename"], 60),
			Date:       releaseDate(fields["Date"]),
			prefix:     prefix,
		}
		if info, err := entry.Info(); err == nil {
			source.FetchedAt = rfc3339(info.ModTime())
			if info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
		if _, known := byPrefix[prefix]; !known {
			prefixes = append(prefixes, prefix)
		}
		byPrefix[prefix] = source
	}
	sort.Strings(prefixes)
	sources := make([]*AptSource, len(prefixes))
	for i, prefix := range prefixes {
		sources[i] = byPrefix[prefix]
		sources[i].ID = i
	}

	// Installed packages by name and architecture.
	wanted := map[installedKey]*aptOffers{}
	byName := map[string]bool{}
	for i := range installed {
		p := &installed[i]
		if p.Type != "deb" || p.Arch == "" {
			continue
		}
		wanted[installedKey{p.Name, p.Arch}] = &aptOffers{pkg: p, from: map[int]bool{}, offers: map[int]string{}}
		byName[p.Name] = true
	}

	// The package indexes: "<prefix><component>_binary-<arch>_Packages", plain or gzip.
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, "_Packages") && !strings.HasSuffix(name, "_Packages.gz") {
			continue
		}
		var source *AptSource
		for _, s := range sources {
			if strings.HasPrefix(name, s.prefix) && (source == nil || len(s.prefix) > len(source.prefix)) {
				source = s
			}
		}
		if source == nil || files >= maxAptIndexFiles || time.Now().After(deadline) {
			continue
		}
		component, _, found := strings.Cut(strings.TrimPrefix(name, source.prefix), "_binary-")
		if !found {
			continue
		}
		files++
		if component = decodeListName(component); component != "" && !contains(source.Components, component) &&
			len(source.Components) < 30 {
			source.Components = append(source.Components, component)
		}
		_ = scanPackagesFile(filepath.Join(dir, name), source.ID, wanted, byName, deadline)
	}

	facts := &AptFacts{Arch: optional(runtime.GOARCH), Sources: make([]AptSource, len(sources)), Packages: []AptPackage{}}
	for i, s := range sources {
		sort.Strings(s.Components)
		facts.Sources[i] = *s
	}
	// When apt update last ran: apt's own stamp where the daily job keeps it, else the newest Release file.
	for _, stamp := range []string{"/var/lib/apt/periodic/update-success-stamp", "/var/lib/apt/periodic/update-stamp"} {
		if info, err := os.Stat(hostPath(root, stamp)); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if !newest.IsZero() {
		facts.ListsUpdatedAt = rfc3339(newest)
	}
	for _, w := range wanted {
		// Third-party: the installed version is offered, but by no source of the distribution.
		from := []int{}
		third := len(w.from) > 0
		for id := range w.from {
			from = append(from, id)
			if isDistributionOrigin(sources[id]) {
				third = false
			}
		}
		if len(w.offers) == 0 && !third {
			continue
		}
		sort.Ints(from)
		if len(from) > MaxAptOffers {
			from = from[:MaxAptOffers]
		}
		offers := []AptOffer{}
		for id, version := range w.offers {
			offers = append(offers, AptOffer{Source: id, Version: version})
		}
		sort.Slice(offers, func(i, j int) bool { return offers[i].Source < offers[j].Source })
		if len(offers) > MaxAptOffers {
			offers = offers[:MaxAptOffers]
		}
		facts.Packages = append(facts.Packages, AptPackage{
			Name: w.pkg.Name, Arch: w.pkg.Arch, Installed: w.pkg.Version, From: from, Offers: offers,
		})
	}
	sort.Slice(facts.Packages, func(i, j int) bool {
		a, b := facts.Packages[i], facts.Packages[j]
		return a.Name < b.Name || (a.Name == b.Name && a.Arch < b.Arch)
	})
	if len(facts.Packages) > MaxAptPackages {
		facts.Packages = facts.Packages[:MaxAptPackages]
	}
	return facts, nil
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// scanPackagesFile streams one package index and records, for the installed packages only, whether this source offers the
// installed version and the newest version it offers above it.
func scanPackagesFile(path string, source int, wanted map[installedKey]*aptOffers, byName map[string]bool, deadline time.Time) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var reader io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		reader = gz
	}
	return ScanPackages(io.LimitReader(reader, maxAptIndexBytes), source, wanted, byName, deadline)
}

// ScanPackages reads the stanzas of a Packages index (only Package, Version and Architecture are looked at).
func ScanPackages(r io.Reader, source int, wanted map[installedKey]*aptOffers, byName map[string]bool, deadline time.Time) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxAptLineBytes)
	var name, version, arch string
	lines := 0
	flush := func() {
		if name != "" && version != "" && arch != "" && byName[name] {
			if w := wanted[installedKey{name, arch}]; w != nil {
				switch c := CompareDebVersions(version, w.pkg.Version); {
				case c == 0:
					w.from[source] = true
				case c > 0:
					if current, ok := w.offers[source]; !ok || CompareDebVersions(version, current) > 0 {
						w.offers[source] = version
					}
				}
			}
		}
		name, version, arch = "", "", ""
	}
	for scanner.Scan() {
		lines++
		if lines%20000 == 0 && time.Now().After(deadline) {
			return errors.New("deadline")
		}
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch key {
		case "Package":
			name = strings.TrimSpace(value)
		case "Version":
			version = strings.TrimSpace(value)
		case "Architecture":
			arch = strings.TrimSpace(value)
		}
	}
	flush()
	return scanner.Err()
}
