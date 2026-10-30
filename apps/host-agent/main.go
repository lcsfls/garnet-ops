// The GarnetOps host agent for hosts without Docker (ADR 0037), run by systemd. It reports the running kernel and the packages
// installed on the host to GarnetOps over HTTPS, signed with the host's Ed25519 key; GarnetOps matches them against its local
// vulnerability database. It only reads.
//
//	garnetops-agent run       report now and then every GARNETOPS_INTERVAL_HOURS
//	garnetops-agent once      report once and exit (non-zero on failure)
//	garnetops-agent version
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

type config struct {
	url, code, stateDir, caFile, hostName string
	interval                              time.Duration
}

func loadConfig() (config, error) {
	c := config{
		url:      os.Getenv("GARNETOPS_URL"),
		code:     os.Getenv("GARNETOPS_ENROLMENT_CODE"),
		stateDir: os.Getenv("GARNETOPS_STATE_DIR"),
		caFile:   os.Getenv("GARNETOPS_CA_FILE"),
		hostName: os.Getenv("GARNETOPS_HOST_NAME"),
		interval: 6 * time.Hour,
	}
	if c.url == "" {
		return c, errors.New("set GARNETOPS_URL")
	}
	if c.stateDir == "" {
		// systemd's StateDirectory= sets this.
		c.stateDir = os.Getenv("STATE_DIRECTORY")
	}
	if c.stateDir == "" {
		c.stateDir = "/var/lib/garnetops-agent"
	}
	if raw := os.Getenv("GARNETOPS_INTERVAL_HOURS"); raw != "" {
		hours, err := strconv.Atoi(raw)
		if err != nil || hours < 1 || hours > 24 {
			return c, errors.New("GARNETOPS_INTERVAL_HOURS must be 1 to 24")
		}
		c.interval = time.Duration(hours) * time.Hour
	}
	if len(c.hostName) > 253 {
		return c, errors.New("GARNETOPS_HOST_NAME is too long")
	}
	return c, nil
}

type storedIdentity struct {
	HostID string `json:"hostId"`
	// Seed is the 32-byte Ed25519 seed, base64.
	Seed string `json:"seed"`
}

func identityPath(dir string) string { return filepath.Join(dir, "identity.json") }

func loadIdentity(dir string) (*Identity, error) {
	data, err := os.ReadFile(identityPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var stored storedIdentity
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(stored.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("identity.json is damaged")
	}
	return &Identity{HostID: stored.HostID, PrivateKey: ed25519.NewKeyFromSeed(seed)}, nil
}

func saveIdentity(dir string, id Identity) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, _ := json.Marshal(storedIdentity{HostID: id.HostID, Seed: base64.StdEncoding.EncodeToString(id.PrivateKey.Seed())})
	tmp := identityPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, identityPath(dir))
}

func hostName(c config) string {
	if c.hostName != "" {
		return c.hostName
	}
	name, _ := os.Hostname()
	return name
}

// ensureIdentity enrols with the one-time code the first time and keeps the key in the state directory (mode 0600).
func ensureIdentity(c config, client *Client) (*Identity, error) {
	if id, err := loadIdentity(c.stateDir); err != nil || id != nil {
		return id, err
	}
	if c.code == "" {
		return nil, errors.New("not enrolled yet: set GARNETOPS_ENROLMENT_CODE to the code from Add agent")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var answer struct {
		HostID string `json:"hostId"`
	}
	err = client.Post("/enrol", map[string]string{
		"code":         c.code,
		"publicKey":    base64.RawURLEncoding.EncodeToString(public),
		"hostname":     hostName(c),
		"agentVersion": version,
	}, nil, &answer)
	if err != nil {
		return nil, err
	}
	id := Identity{HostID: answer.HostID, PrivateKey: private}
	if err := saveIdentity(c.stateDir, id); err != nil {
		return nil, err
	}
	fmt.Printf("agent: enrolled as %s\n", id.HostID)
	return &id, nil
}

// reportOnce sends the inventory (kernel, distribution, digest of the package list) and, if asked, the package list.
func reportOnce(c config, client *Client) (int, error) {
	id, err := ensureIdentity(c, client)
	if err != nil {
		return 0, err
	}
	root := rootDir()
	osr := readOSRelease(root)
	packages, err := ReadPackages(root, osr)
	if err != nil {
		fmt.Printf("agent: packages: %v\n", err)
	}
	packages = Cap(packages)
	inventory := map[string]any{
		"hostname":     hostName(c),
		"agentVersion": version,
		"os":           optional(osr.PrettyName),
		"kernel":       readKernel(root, osr),
		"runtime":      "systemd",
		"containers":   []any{},
		"images":       []any{},
	}
	if len(packages) > 0 {
		inventory["hostPackagesDigest"] = Digest(packages)
	}
	var answer struct {
		NeedHostPackages bool `json:"needHostPackages"`
	}
	if err := client.Post("/inventory", inventory, id, &answer); err != nil {
		return 0, err
	}
	if !answer.NeedHostPackages || len(packages) == 0 {
		return 0, nil
	}
	distro := osr.ID
	if osr.VersionID != "" {
		distro += " " + osr.VersionID
	}
	err = client.Post("/host-packages", map[string]any{
		"distro":   optional(distro),
		"digest":   Digest(packages),
		"packages": packages,
	}, id, nil)
	if err != nil {
		return 0, err
	}
	return len(packages), nil
}

func tick(c config, client *Client) bool {
	sent, err := reportOnce(c, client)
	var server *ServerError
	switch {
	case err == nil && sent > 0:
		fmt.Printf("agent: reported, %d packages sent\n", sent)
	case err == nil:
		fmt.Println("agent: reported, package list unchanged")
	case errors.As(err, &server) && server.Status == 401:
		fmt.Println("agent: GarnetOps refused this host (removed, or the code is not valid); remove the agent or enrol again")
	case errors.As(err, &server) && server.Code == "module-off":
		fmt.Println("agent: hosts and containers are switched off in GarnetOps; trying again later")
	default:
		fmt.Printf("agent: report failed: %v\n", err)
	}
	return err == nil
}

func main() {
	command := "run"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	if command == "version" {
		fmt.Println(version)
		return
	}
	if command != "run" && command != "once" {
		fmt.Fprintf(os.Stderr, "unknown command: %s (run, once or version)\n", command)
		os.Exit(2)
	}
	c, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: %v\n", err)
		os.Exit(2)
	}
	client, err := NewClient(c.url, c.caFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent: %v\n", err)
		os.Exit(2)
	}
	if command == "once" {
		if !tick(c, client) {
			os.Exit(1)
		}
		return
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	tick(c, client)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			tick(c, client)
		case <-stop:
			return
		}
	}
}
