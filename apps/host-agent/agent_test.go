package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

var ubuntu = OSRelease{ID: "ubuntu", IDLike: "debian", VersionID: "24.04", PrettyName: "Ubuntu 24.04.1 LTS"}

func TestOSRelease(t *testing.T) {
	got := ParseOSRelease("# comment\nNAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n")
	if got != ubuntu {
		t.Fatalf("got %+v", got)
	}
}

func TestDpkgStatus(t *testing.T) {
	status := strings.Join([]string{
		"Package: libssl3t64\nStatus: install ok installed\nArchitecture: amd64\nSource: openssl\nVersion: 3.0.13-0ubuntu3.4\nDescription: Secure Sockets Layer toolkit\n multi-line description",
		"Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2.21-2ubuntu4",
		"Package: removed-pkg\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 1.0",
		"Package: linux-libc-dev\nStatus: install ok installed\nArchitecture: amd64\nSource: linux (6.8.0-45.45)\nVersion: 6.8.0-45.45",
	}, "\n\n")
	got := ParseDpkgStatus(status, ubuntu)
	want := []string{
		"pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.4?arch=amd64&upstream=openssl&distro=ubuntu-24.04",
		"pkg:deb/ubuntu/bash@5.2.21-2ubuntu4?arch=amd64&distro=ubuntu-24.04",
		"pkg:deb/ubuntu/linux-libc-dev@6.8.0-45.45?arch=amd64&upstream=linux%406.8.0-45.45&distro=ubuntu-24.04",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d packages: %+v", len(got), got)
	}
	for i := range want {
		if got[i].Purl != want[i] || got[i].Type != "deb" {
			t.Errorf("package %d: got %s", i, got[i].Purl)
		}
	}
}

func TestApkInstalled(t *testing.T) {
	alpine := OSRelease{ID: "alpine", VersionID: "3.20.3", PrettyName: "Alpine Linux v3.20"}
	got := ParseApkInstalled("C:Q1abc=\nP:musl\nV:1.2.5-r0\nA:x86_64\no:musl\n\nP:busybox\nV:1.36.1-r29\nA:x86_64\no:busybox\n", alpine)
	if len(got) != 2 || got[0].Purl != "pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&upstream=musl&distro=alpine-3.20.3" {
		t.Fatalf("got %+v", got)
	}
}

func TestRpmOutput(t *testing.T) {
	rhel := OSRelease{ID: "rhel", VersionID: "9.4", PrettyName: "Red Hat Enterprise Linux 9.4 (Plow)"}
	out := "openssl\t1\t3.0.7\t27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\n" +
		"bash\t0\t5.1.8\t9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm\n" +
		"gpg-pubkey\t0\tfd431d51\t4ae0493b\t(none)\t(none)\n"
	got := ParseRpmOutput(out, rhel)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Purl != "pkg:rpm/rhel/openssl@3.0.7-27.el9?arch=x86_64&epoch=1&upstream=openssl-3.0.7-27.el9.src.rpm&distro=rhel-9.4" {
		t.Errorf("got %s", got[0].Purl)
	}
	if strings.Contains(got[1].Purl, "epoch=") {
		t.Errorf("epoch 0 must be left out: %s", got[1].Purl)
	}
}

func TestDigestIgnoresOrderAndCapRemovesDuplicates(t *testing.T) {
	a := []Package{{Purl: "pkg:deb/x/a@1"}, {Purl: "pkg:deb/x/b@1"}}
	b := []Package{{Purl: "pkg:deb/x/b@1"}, {Purl: "pkg:deb/x/a@1"}}
	if Digest(a) != Digest(b) || len(Digest(a)) != 64 {
		t.Fatal("the digest must not depend on the order")
	}
	if got := Cap([]Package{{Purl: "p:1"}, {Purl: "p:1"}, {Purl: "p:0"}}); len(got) != 2 || got[0].Purl != "p:0" {
		t.Fatalf("got %+v", got)
	}
}

// The signed text must be byte for byte what signingInput in @garnetops/core/agent builds (value taken from it).
func TestSigningInputMatchesTheServer(t *testing.T) {
	got := string(SigningInput("post", "/api/v1/agent/inventory", 1767225600000, "AAAAAAAAAAAAAAAAAAAAAA", []byte(`{"a":1}`)))
	want := "POST\n/api/v1/agent/inventory\n1767225600000\nAAAAAAAAAAAAAAAAAAAAAA\n015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
	if got != want {
		t.Fatalf("got %q", got)
	}
}

// The header must pass the server's parser (HEADER in @garnetops/core/agent) and verify with the host's public key.
func TestSignatureHeader(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	now := time.UnixMilli(1767225600123)
	header, err := SignatureHeader(Identity{HostID: "hst_abc123", PrivateKey: private}, "POST", "/api/v1/agent/inventory", []byte("{}"), now)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`^GarnetOps-Agent host="(hst_[A-Za-z0-9_-]{1,64})", ts="(\d{13})", nonce="([A-Za-z0-9_-]{22})", sig="([A-Za-z0-9_-]{86})"$`).FindStringSubmatch(header)
	if m == nil {
		t.Fatalf("header does not match the server's format: %s", header)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(m[4])
	if !ed25519.Verify(public, SigningInput("POST", "/api/v1/agent/inventory", 1767225600123, m[3], []byte("{}")), sig) {
		t.Fatal("signature does not verify")
	}
}

func TestClientRefusesPlainHTTPInReleaseBuilds(t *testing.T) {
	if allowHTTP {
		t.Skip("e2e build")
	}
	if _, err := NewClient("http://garnetops.example.lan", ""); err == nil {
		t.Fatal("http:// must be refused")
	}
	if _, err := NewClient("https://user:pw@garnetops.example.lan", ""); err == nil {
		t.Fatal("credentials in the address must be refused")
	}
	if _, err := NewClient("https://garnetops.example.lan", ""); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityIsPrivateToTheAgent(t *testing.T) {
	dir := t.TempDir()
	_, private, _ := ed25519.GenerateKey(nil)
	if err := saveIdentity(dir, Identity{HostID: "hst_x", PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	info, _ := statMode(identityPath(dir))
	if info != 0o600 {
		t.Fatalf("mode %o", info)
	}
	loaded, err := loadIdentity(dir)
	if err != nil || loaded.HostID != "hst_x" || !loaded.PrivateKey.Equal(private) {
		t.Fatalf("got %+v %v", loaded, err)
	}
}

func statMode(path string) (uint32, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return uint32(info.Mode().Perm()), nil
}
