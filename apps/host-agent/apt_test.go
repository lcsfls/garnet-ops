package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The same pairs as packages/core/src/deb-version.test.ts, each checked against `dpkg --compare-versions a lt b`.
func TestCompareDebVersions(t *testing.T) {
	ordered := [][2]string{
		{"1.0", "1.1"}, {"1.0", "1.0-1"}, {"1.0-1", "1.0-2"}, {"1.0-1", "1.0-1+b1"}, {"1.0~rc1", "1.0"},
		{"1.0~rc1-1", "1.0-1"}, {"1.0~~", "1.0~"}, {"1.0~", "1.0"}, {"1.0", "1.0a"}, {"1.0", "1.0."}, {"1.0a", "1.0."},
		{"1.0", "1.0+"}, {"2.4-1", "2.30-1"}, {"1.09", "1.10"}, {"9.9", "1:0.1"}, {"1:1.0", "2:0.1"},
		{"3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5"}, {"3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.10"},
		{"2.9.14+dfsg-1.3ubuntu3", "2.9.14+dfsg-1.3ubuntu3.1"}, {"1.2.3-1ubuntu0.1", "1.2.3-1ubuntu0.1+esm1"},
		{"1.2.3-1ubuntu0.1+esm1", "1.2.3-1ubuntu0.1+esm2"}, {"1.2.3-1ubuntu0.2~esm1", "1.2.3-1ubuntu0.2"},
		{"6.1.112-1", "6.1.115-1"}, {"6.1.76-1~bpo11+1", "6.1.76-1"}, {"8.2.26-1~deb12u1", "8.2.26-1"},
		{"8.3.6-0ubuntu0.24.04.2", "8.3.6-0ubuntu0.24.04.3"},
		{"8.3.13-1+ubuntu24.04.1+deb.sury.org+1", "8.3.14-1+ubuntu24.04.1+deb.sury.org+1"}, {"0.0.0-0", "0:0.0.1"},
	}
	for _, pair := range ordered {
		if CompareDebVersions(pair[0], pair[1]) >= 0 || CompareDebVersions(pair[1], pair[0]) <= 0 {
			t.Errorf("%s < %s", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{{"1.0-1", "1.0-1"}, {"0:1.0-1", "1.0-1"}, {"1.001", "1.1"}} {
		if CompareDebVersions(pair[0], pair[1]) != 0 {
			t.Errorf("%s = %s", pair[0], pair[1])
		}
	}
	if CompareDebVersions("not a version", "0.1") >= 0 {
		t.Error("text that is not a version sorts first")
	}
}

func TestParseListName(t *testing.T) {
	host, path, suite, prefix, ok := ParseListName("mirror.example.lan_ubuntu_dists_noble-security_InRelease")
	if !ok || host != "mirror.example.lan" || path != "ubuntu" || suite != "noble-security" ||
		prefix != "mirror.example.lan_ubuntu_dists_noble-security_" {
		t.Fatalf("got %q %q %q %q %v", host, path, suite, prefix, ok)
	}
	_, path, _, _, _ = ParseListName("ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_InRelease")
	if path != "ondrej/php/ubuntu" {
		t.Errorf("path %q", path)
	}
	_, path, suite, _, _ = ParseListName("repo.example.lan:8080_my%5frepo_dists_stable_Release")
	if path != "my_repo" || suite != "stable" {
		t.Errorf("path %q suite %q", path, suite)
	}
	for _, bad := range []string{"lock", "partial", "x_Packages", "nodists_InRelease", "bad host!_x_dists_a_InRelease"} {
		if _, _, _, _, ok := ParseListName(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
}

const inRelease = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Origin: Ubuntu
Label: Ubuntu
Suite: noble-security
Version: 24.04
Codename: noble
Date: Tue, 03 Nov 2026 08:15:00 UTC
Architectures: amd64 arm64
Components: main restricted universe multiverse
Description: Ubuntu Noble 24.04
SHA256:
 0123 4567 main/binary-amd64/Packages
Origin: not this one
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEE
-----END PGP SIGNATURE-----
`

func TestParseReleaseFields(t *testing.T) {
	fields := ParseReleaseFields(inRelease)
	if fields["Origin"] != "Ubuntu" || fields["Codename"] != "noble" || fields["Hash"] != "" {
		t.Fatalf("got %+v", fields)
	}
	if got := releaseDate(fields["Date"]); got == nil || *got != "2026-11-03T08:15:00Z" {
		t.Errorf("date %v", got)
	}
	if releaseDate("yesterday") != nil {
		t.Error("a date that is none")
	}
}

// writeLists writes a synthetic /var/lib/apt/lists: a mirror of Ubuntu (release, updates, security) and a PPA.
func writeLists(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, "var/lib/apt/lists")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, text string, age time.Duration) {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	release := func(origin, suite string) string {
		return "Origin: " + origin + "\nLabel: " + origin + "\nSuite: " + suite + "\nCodename: noble\nDate: Tue, 03 Nov 2026 08:15:00 UTC\nSHA256:\n abc 1 x\n"
	}
	m := "mirror.example.lan_ubuntu_dists_"
	write(m+"noble_InRelease", release("Ubuntu", "noble"), 48*time.Hour)
	write(m+"noble_Release", "Origin: ignored\n", 48*time.Hour)
	write(m+"noble-updates_InRelease", release("Ubuntu", "noble-updates"), 2*time.Hour)
	write(m+"noble-security_InRelease", release("Ubuntu", "noble-security"), 3*time.Hour)
	write(m+"noble_main_binary-amd64_Packages", strings.Join([]string{
		"Package: libssl3t64\nArchitecture: amd64\nVersion: 3.0.13-0ubuntu3\nDescription: TLS\n long text",
		"Package: bash\nArchitecture: amd64\nVersion: 5.2.21-2ubuntu4",
		"Package: unrelated\nArchitecture: amd64\nVersion: 9.9",
	}, "\n\n")+"\n", 48*time.Hour)
	write(m+"noble-updates_main_binary-amd64_Packages", "Package: libssl3t64\nArchitecture: amd64\nVersion: 3.0.13-0ubuntu3.4\n", 2*time.Hour)
	// The security pocket offers a newer build twice (only the newest counts) and one for another architecture.
	write(m+"noble-security_main_binary-amd64_Packages",
		"Package: libssl3t64\nArchitecture: amd64\nVersion: 3.0.13-0ubuntu3.5\n\n"+
			"Package: libssl3t64\nArchitecture: amd64\nVersion: 3.0.13-0ubuntu3.10\n\n"+
			"Package: libssl3t64\nArchitecture: i386\nVersion: 3.0.13-0ubuntu3.99\n", 3*time.Hour)
	p := "ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_"
	write(p+"InRelease", "Origin: LP-PPA-ondrej-php\nLabel: PPA for PHP\nSuite: noble\nCodename: noble\n", 30*time.Hour)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("Package: php8.3-cli\nArchitecture: amd64\nVersion: 8.3.13-1+ubuntu24.04.1+deb.sury.org+1\n\n" +
		"Package: php8.3-cli\nArchitecture: amd64\nVersion: 8.3.14-1+ubuntu24.04.1+deb.sury.org+1\n\n" +
		"broken stanza without a colon\n\nPackage: php8.3-common\nArchitecture: amd64\nVersion: 8.3.13-1+ubuntu24.04.1+deb.sury.org+1\n"))
	_ = zw.Close()
	write(p+"main_binary-amd64_Packages.gz", gz.String(), 30*time.Hour)
	write("lock", "", 0)
	write("auxfiles_should_be_ignored", "x", 0)
}

func TestReadAptFacts(t *testing.T) {
	root := t.TempDir()
	writeLists(t, root)
	installed := []Package{
		{Name: "libssl3t64", Version: "3.0.13-0ubuntu3.4", Type: "deb", Arch: "amd64"},
		{Name: "bash", Version: "5.2.21-2ubuntu4", Type: "deb", Arch: "amd64"},
		{Name: "php8.3-cli", Version: "8.3.13-1+ubuntu24.04.1+deb.sury.org+1", Type: "deb", Arch: "amd64"},
		{Name: "php8.3-common", Version: "8.3.13-1+ubuntu24.04.1+deb.sury.org+1", Type: "deb", Arch: "amd64"},
		{Name: "local-tool", Version: "1.0", Type: "deb", Arch: "amd64"},
	}
	facts, err := ReadAptFacts(root, installed, time.Now().Add(time.Minute))
	if err != nil || facts == nil {
		t.Fatalf("facts %v, err %v", facts, err)
	}
	if len(facts.Sources) != 4 {
		t.Fatalf("sources: %+v", facts.Sources)
	}
	suites := map[string]AptSource{}
	for _, s := range facts.Sources {
		suites[s.Host+" "+s.Suite] = s
	}
	sec := suites["mirror.example.lan noble-security"]
	if *sec.Origin != "Ubuntu" || *sec.Date != "2026-11-03T08:15:00Z" || sec.FetchedAt == nil ||
		strings.Join(sec.Components, ",") != "main" {
		t.Errorf("security source %+v", sec)
	}
	if o := suites["mirror.example.lan noble"].Origin; o == nil || *o != "Ubuntu" {
		t.Error("InRelease wins over Release")
	}
	ppa := suites["ppa.launchpadcontent.net noble"]
	if ppa.Path != "ondrej/php/ubuntu" || strings.Join(ppa.Components, ",") != "main" {
		t.Errorf("ppa %+v", ppa)
	}

	// Only what matters is sent: libssl (newer offered), php8.3-cli (newer offered, third party), php8.3-common (third party).
	byName := map[string]AptPackage{}
	for _, p := range facts.Packages {
		byName[p.Name] = p
	}
	if len(byName) != 3 {
		t.Fatalf("packages %+v", facts.Packages)
	}
	ssl := byName["libssl3t64"]
	if len(ssl.Offers) != 1 || ssl.Offers[0].Version != "3.0.13-0ubuntu3.10" || ssl.Offers[0].Source != sec.ID ||
		len(ssl.From) != 1 || ssl.From[0] != suites["mirror.example.lan noble-updates"].ID {
		t.Errorf("libssl %+v", ssl)
	}
	cli := byName["php8.3-cli"]
	if len(cli.From) != 1 || cli.From[0] != ppa.ID || cli.Offers[0].Version != "8.3.14-1+ubuntu24.04.1+deb.sury.org+1" {
		t.Errorf("php8.3-cli %+v", cli)
	}
	if common := byName["php8.3-common"]; len(common.Offers) != 0 || len(common.From) != 1 {
		t.Errorf("php8.3-common %+v", common)
	}
	// The newest Release file (two hours old) says when apt update last ran.
	updated, _ := time.Parse(time.RFC3339, *facts.ListsUpdatedAt)
	if d := time.Since(updated); d < 119*time.Minute || d > 121*time.Minute {
		t.Errorf("lists updated %v ago", d)
	}
	// What goes over the wire: no list file content, no internal fields.
	wire, _ := json.Marshal(facts)
	if strings.Contains(string(wire), "unrelated") || strings.Contains(string(wire), "prefix") {
		t.Errorf("sent too much: %s", wire)
	}
}

func TestReadAptFactsWithoutLists(t *testing.T) {
	facts, err := ReadAptFacts(t.TempDir(), nil, time.Now().Add(time.Minute))
	if facts != nil || err != nil {
		t.Fatalf("got %+v %v", facts, err)
	}
}

func TestScanPackagesStopsAtTheDeadline(t *testing.T) {
	text := strings.Repeat("Package: a\nArchitecture: amd64\nVersion: 1\n\n", 30000)
	wanted := map[installedKey]*aptOffers{}
	if err := ScanPackages(strings.NewReader(text), 0, wanted, map[string]bool{}, time.Now().Add(-time.Second)); err == nil {
		t.Error("a scan past its deadline stops")
	}
}
