package main

// What the agent reads on the host (ADR 0037): the distribution from os-release, the running kernel from /proc, and the installed
// packages from the package manager's own database (dpkg, apk) or from rpm. Nothing is executed except rpm, nothing is written.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// MaxPackages is the server's limit for one list (packagesSchema in @garnetops/core/agent).
const MaxPackages = 50000

// OSRelease holds the fields of /etc/os-release the agent needs.
type OSRelease struct {
	ID         string
	IDLike     string
	VersionID  string
	PrettyName string
}

// Package is one installed package as the server expects it.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	Purl    string `json:"purl"`
}

// Kernel is the running kernel and the distribution, as the inventory carries it.
type Kernel struct {
	Release          string  `json:"release"`
	ProcVersion      *string `json:"procVersion"`
	VersionSignature *string `json:"versionSignature"`
	OSName           *string `json:"osName"`
	OSVersion        *string `json:"osVersion"`
	Architecture     *string `json:"architecture"`
}

func hostPath(root, path string) string { return filepath.Join(root, path) }

func readSmall(path string, limit int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, limit)
	n, _ := f.Read(buf)
	return strings.TrimSpace(string(buf[:n])), nil
}

// ParseOSRelease reads the KEY=value lines of os-release, with or without quotes.
func ParseOSRelease(text string) OSRelease {
	values := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(key, "#") {
			continue
		}
		values[key] = strings.Trim(value, `"'`)
	}
	return OSRelease{ID: values["ID"], IDLike: values["ID_LIKE"], VersionID: values["VERSION_ID"], PrettyName: values["PRETTY_NAME"]}
}

func readOSRelease(root string) OSRelease {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if text, err := readSmall(hostPath(root, path), 8192); err == nil {
			return ParseOSRelease(text)
		}
	}
	return OSRelease{}
}

// machine is what `uname -m` says on the architectures the agent is built for.
func machine() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func readKernel(root string, osr OSRelease) *Kernel {
	release, err := readSmall(hostPath(root, "/proc/sys/kernel/osrelease"), 120)
	if err != nil || release == "" {
		return nil
	}
	procVersion, _ := readSmall(hostPath(root, "/proc/version"), 400)
	signature, _ := readSmall(hostPath(root, "/proc/version_signature"), 200)
	arch := machine()
	return &Kernel{
		Release:          release,
		ProcVersion:      optional(procVersion),
		VersionSignature: optional(signature),
		OSName:           optional(osr.PrettyName),
		OSVersion:        optional(osr.VersionID),
		Architecture:     &arch,
	}
}

func distroQualifier(osr OSRelease) string {
	if osr.ID == "" || osr.VersionID == "" {
		return ""
	}
	return osr.ID + "-" + osr.VersionID
}

// purl builds a package URL the way syft does, so grype matches the host's packages as it matches an image's.
func purl(kind, namespace, name, version string, qualifiers [][2]string) string {
	var q []string
	for _, kv := range qualifiers {
		if kv[1] != "" {
			q = append(q, kv[0]+"="+url.QueryEscape(kv[1]))
		}
	}
	out := fmt.Sprintf("pkg:%s/%s/%s@%s", kind, url.PathEscape(namespace), url.PathEscape(name), url.PathEscape(version))
	if len(q) > 0 {
		out += "?" + strings.Join(q, "&")
	}
	return out
}

// ParseDpkgStatus reads /var/lib/dpkg/status: every package whose status is "install ok installed".
func ParseDpkgStatus(text string, osr OSRelease) []Package {
	var out []Package
	for _, block := range strings.Split(text, "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue // a continuation line of a long field (the description)
			}
			if key, value, ok := strings.Cut(line, ":"); ok {
				fields[key] = strings.TrimSpace(value)
			}
		}
		if fields["Package"] == "" || fields["Version"] == "" || fields["Status"] != "install ok installed" {
			continue
		}
		upstream := ""
		if source := fields["Source"]; source != "" {
			name, version, hasVersion := strings.Cut(source, " ")
			upstream = name
			if hasVersion {
				upstream = name + "@" + strings.Trim(version, "()")
			}
		}
		namespace := osr.ID
		if namespace == "" {
			namespace = "debian"
		}
		out = append(out, Package{
			Name:    fields["Package"],
			Version: fields["Version"],
			Type:    "deb",
			Purl: purl("deb", namespace, fields["Package"], fields["Version"], [][2]string{
				{"arch", fields["Architecture"]}, {"upstream", upstream}, {"distro", distroQualifier(osr)},
			}),
		})
	}
	return out
}

// ParseApkInstalled reads /lib/apk/db/installed: P name, V version, A arch, o origin.
func ParseApkInstalled(text string, osr OSRelease) []Package {
	var out []Package
	for _, block := range strings.Split(text, "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if len(line) > 2 && line[1] == ':' {
				fields[line[:1]] = line[2:]
			}
		}
		if fields["P"] == "" || fields["V"] == "" {
			continue
		}
		out = append(out, Package{
			Name:    fields["P"],
			Version: fields["V"],
			Type:    "apk",
			Purl: purl("apk", "alpine", fields["P"], fields["V"], [][2]string{
				{"arch", fields["A"]}, {"upstream", fields["o"]}, {"distro", distroQualifier(osr)},
			}),
		})
	}
	return out
}

// RpmQueryFormat is what the agent asks rpm for: one tab-separated line per package.
const RpmQueryFormat = `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n`

// ParseRpmOutput reads the lines of `rpm -qa --qf RpmQueryFormat`.
func ParseRpmOutput(text string, osr OSRelease) []Package {
	var out []Package
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 6 || parts[0] == "" || parts[0] == "gpg-pubkey" {
			continue
		}
		name, epoch, version, release, arch, source := parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
		if epoch == "0" {
			epoch = ""
		}
		if source == "(none)" {
			source = ""
		}
		full := version + "-" + release
		namespace := osr.ID
		if namespace == "" {
			namespace = "redhat"
		}
		out = append(out, Package{
			Name:    name,
			Version: full,
			Type:    "rpm",
			Purl: purl("rpm", namespace, name, full, [][2]string{
				{"arch", arch}, {"epoch", epoch}, {"upstream", source}, {"distro", distroQualifier(osr)},
			}),
		})
	}
	return out
}

func readRpm(osr OSRelease) ([]Package, error) {
	bin := rpmBinary()
	if bin == "" {
		for _, candidate := range []string{"/usr/bin/rpm", "/bin/rpm"} {
			if _, err := os.Stat(candidate); err == nil {
				bin = candidate
				break
			}
		}
	}
	if bin == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-qa", "--qf", RpmQueryFormat)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("rpm: %w", err)
	}
	return ParseRpmOutput(string(output), osr), nil
}

// ReadPackages finds the package manager of the host and reads its list. An empty list with no error: no known package manager.
func ReadPackages(root string, osr OSRelease) ([]Package, error) {
	if text, err := os.ReadFile(hostPath(root, "/var/lib/dpkg/status")); err == nil {
		return ParseDpkgStatus(string(text), osr), nil
	}
	if text, err := os.ReadFile(hostPath(root, "/lib/apk/db/installed")); err == nil {
		return ParseApkInstalled(string(text), osr), nil
	}
	packages, err := readRpm(osr)
	if err != nil {
		return nil, err
	}
	if packages == nil {
		return nil, errors.New("no package manager found (dpkg, apk or rpm)")
	}
	return packages, nil
}

// Cap keeps the first MaxPackages packages in purl order, without duplicates.
func Cap(packages []Package) []Package {
	sort.Slice(packages, func(i, j int) bool { return packages[i].Purl < packages[j].Purl })
	out := packages[:0]
	seen := map[string]bool{}
	for _, p := range packages {
		if seen[p.Purl] {
			continue
		}
		seen[p.Purl] = true
		out = append(out, p)
		if len(out) == MaxPackages {
			break
		}
	}
	return out
}

// Digest is the SHA-256 (hex) over the sorted package URLs: the server asks for the list only when it changed.
func Digest(packages []Package) string {
	purls := make([]string, len(packages))
	for i, p := range packages {
		purls[i] = p.Purl
	}
	sort.Strings(purls)
	sum := sha256.Sum256([]byte(strings.Join(purls, "\n")))
	return hex.EncodeToString(sum[:])
}
