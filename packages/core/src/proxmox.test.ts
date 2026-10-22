/**
 * Proxmox VE parsing against recorded (synthetic) answers of PVE 8.x and 9.x, the address and
 * token checks, the read-only path allow-list, the privilege check and the staleness rules.
 * The fixtures use documentation addresses (192.0.2.0/24, 2001:db8::/32) and example names.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  certificateFingerprint,
  checkClusterName,
  checkProxmoxUrl,
  checkTokenId,
  cleanAddresses,
  coveredByBackupJob,
  extraPrivileges,
  hasAnyPrivilege,
  isNodeName,
  isReadPath,
  normalizeFingerprint,
  parseAgentInterfaces,
  parseAptUpdates,
  parseBackupContent,
  parseBackupJobs,
  parseClusterStatus,
  parseGuestConfig,
  parseHaResources,
  parseLxcInterfaces,
  parseNodeStatus,
  parseResources,
  parseSnapshots,
  parseTags,
  parseVersion,
  privilegesAcknowledged,
  unwrap,
} from "./proxmox.ts";
import { parseProxmoxError, proxmoxErrorMessage } from "./proxmox-errors.ts";
import {
  GUEST_FLAGS,
  type GuestFlagInput,
  guestFlags,
  parseProxmoxSourceRef,
  proxmoxSourceRef,
  STALE_BACKUP_DAYS,
  STALE_SNAPSHOT_DAYS,
  STALE_STOPPED_DAYS,
} from "./proxmox-flags.ts";

const fixture = (version: "pve8" | "pve9", name: string): unknown =>
  unwrap(
    JSON.parse(
      readFileSync(
        fileURLToPath(new URL(`../test/fixtures/proxmox/${version}/${name}.json`, import.meta.url)),
        "utf8",
      ),
    ),
  );

describe("API address", () => {
  it("accepts https with an optional port and normalises it", () => {
    expect(checkProxmoxUrl("https://pve1.example.lan")).toEqual({
      ok: true,
      url: "https://pve1.example.lan:8006",
      host: "pve1.example.lan",
      port: 8006,
    });
    expect(checkProxmoxUrl("  HTTPS://PVE1.Example.LAN:8443/ ")).toMatchObject({
      ok: true,
      url: "https://pve1.example.lan:8443",
      port: 8443,
    });
    expect(checkProxmoxUrl("https://192.0.2.11:8006")).toMatchObject({ ok: true, host: "192.0.2.11" });
    expect(checkProxmoxUrl("https://[2001:db8::11]:8006")).toMatchObject({
      ok: true,
      url: "https://[2001:db8::11]:8006",
      host: "2001:db8::11",
    });
  });

  it.each([
    ["", "empty"],
    ["http://pve1.example.lan:8006", "notHttps"],
    ["pve1.example.lan:8006", "notHttps"],
    ["ftp://pve1.example.lan", "notHttps"],
    ["https://admin:secret@pve1.example.lan", "credentials"],
    ["https://pve1.example.lan/api2/json", "path"],
    ["https://pve1.example.lan/?x=1", "path"],
    ["https://pve1.example.lan/#frag", "path"],
    ["https://127.0.0.1:8006", "address"],
    ["https://127.1", "address"],
    ["https://localhost:8006", "address"],
    ["https://app.localhost", "address"],
    ["https://169.254.169.254", "address"],
    ["https://[::1]:8006", "address"],
    ["https://[fe80::1]:8006", "address"],
    ["https://224.0.0.1", "address"],
    ["https://0.0.0.0", "address"],
    ["https://pve1.example.lan:99999", "invalid"],
    ["https://", "invalid"],
  ])("refuses %j (%s)", (value, problem) => {
    expect(checkProxmoxUrl(value)).toEqual({ ok: false, problem });
  });

  it("refuses an address that is far too long", () => {
    expect(checkProxmoxUrl(`https://${"a".repeat(400)}.example.lan`)).toEqual({
      ok: false,
      problem: "tooLong",
    });
  });
});

describe("token and names", () => {
  it("accepts user@realm!tokenid", () => {
    expect(checkTokenId("garnetops@pve!inventory")).toEqual({ ok: true, value: "garnetops@pve!inventory" });
    expect(checkTokenId(" svc-audit@pam!ro_1 ")).toEqual({ ok: true, value: "svc-audit@pam!ro_1" });
  });

  it("never accepts root, nor something that is not a token id", () => {
    expect(checkTokenId("root@pam!garnetops")).toEqual({ ok: false, problem: "root" });
    expect(checkTokenId("ROOT@pam!x1")).toEqual({ ok: false, problem: "root" });
    for (const bad of [
      "garnetops@pve",
      "garnetops!inventory",
      "a b@pve!x1",
      "garnetops@pve!",
      "@pve!abc",
      "",
    ]) {
      expect(checkTokenId(bad)).toEqual({ ok: false, problem: "invalid" });
    }
  });

  it("checks the display name", () => {
    expect(checkClusterName("  Lab  ")).toBe("Lab");
    expect(checkClusterName("")).toBeNull();
    expect(checkClusterName("a\u0007b")).toBeNull();
    expect(checkClusterName("x".repeat(81))).toBeNull();
  });
});

describe("certificate fingerprints", () => {
  it("writes SHA-256 the way Proxmox shows it", () => {
    const f = certificateFingerprint(Buffer.from("example"));
    expect(f).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    expect(normalizeFingerprint(f.toLowerCase())).toBe(f);
    expect(normalizeFingerprint("AA:BB")).toBeNull();
    expect(normalizeFingerprint(f.replace(/:/g, ""))).toBeNull();
  });
});

describe("read-only path allow-list", () => {
  it("allows exactly the endpoints the sync reads", () => {
    for (const path of [
      "/version",
      "/cluster/status",
      "/cluster/resources",
      "/cluster/ha/resources",
      "/cluster/backup",
      "/access/permissions",
      "/nodes/pve1/status",
      "/nodes/pve1/apt/update",
      "/nodes/pve-2/qemu/100/config",
      "/nodes/pve1/lxc/200/snapshot",
      "/nodes/pve1/qemu/100/agent/network-get-interfaces",
      "/nodes/pve1/lxc/200/interfaces",
      "/nodes/pve1/storage/nas-backup/content",
    ]) {
      expect(isReadPath(path), path).toBe(true);
    }
  });

  it("refuses everything that acts, reads secrets or leaves the inventory", () => {
    for (const path of [
      "/nodes/pve1/qemu/100/status/start",
      "/nodes/pve1/qemu/100/status/current",
      "/nodes/pve1/qemu/100/agent/exec",
      "/nodes/pve1/qemu/100/agent/file-read",
      "/nodes/pve1/lxc/200/termproxy",
      "/nodes/pve1/qemu/100/vncproxy",
      "/nodes/pve1/apt/update/extra",
      "/nodes/pve1/apt/changelog",
      "/nodes/pve1/tasks",
      "/nodes/pve1/storage/nas-backup/upload",
      "/access/users",
      "/access/ticket",
      "/access/permissions/extra",
      "/cluster/config",
      "/cluster/acme/account",
      "/nodes/pve1/../../access/users",
      "/nodes/pve1/qemu/0/config",
      "/nodes/pve1/qemu/007/config",
      "/nodes/pve 1/status",
      "/nodes//status",
      "/api2/json/version",
      "version",
      "/version?x=1",
      "/version/",
    ]) {
      expect(isReadPath(path), path).toBe(false);
    }
  });

  it("only names that can be a node", () => {
    expect(isNodeName("pve1")).toBe(true);
    expect(isNodeName("pve1.example")).toBe(false);
    expect(isNodeName("-pve")).toBe(false);
    expect(isNodeName("pve/../x")).toBe(false);
  });
});

describe("version and cluster status", () => {
  it("reads the version of PVE 8 and 9", () => {
    expect(parseVersion(fixture("pve8", "version"))).toBe("8.2.4");
    expect(parseVersion(fixture("pve9", "version"))).toBe("9.0.3");
  });

  it("does not take something else for Proxmox", () => {
    expect(parseVersion({})).toBeNull();
    expect(parseVersion({ version: "<script>" })).toBeNull();
    expect(parseVersion("8.2")).toBeNull();
    expect(parseVersion(null)).toBeNull();
  });

  it("reads the cluster name, quorum and node states", () => {
    const s = parseClusterStatus(fixture("pve8", "cluster-status"));
    expect(s.name).toBe("lab-cluster");
    expect(s.quorate).toBe(true);
    expect([...s.nodes]).toEqual([
      ["pve1", true],
      ["pve2", true],
      ["pve3", false],
    ]);
  });

  it("has no cluster name on a stand-alone node", () => {
    const s = parseClusterStatus(fixture("pve9", "cluster-status"));
    expect(s.name).toBeNull();
    expect(s.quorate).toBeNull();
    expect(s.nodes.get("pve1")).toBe(true);
  });
});

describe("cluster resources", () => {
  const r = parseResources(fixture("pve8", "cluster-resources"));

  it("reads nodes, guests and storage and ignores the rest", () => {
    expect(r.nodes.map((n) => [n.name, n.online])).toEqual([
      ["pve1", true],
      ["pve2", true],
      ["pve3", false],
    ]);
    expect(r.guests.map((g) => g.vmid).sort((a, b) => a - b)).toEqual([
      100, 101, 102, 103, 200, 201, 202, 9000,
    ]);
    expect(r.storages.map((s) => `${s.node}/${s.name}`)).toEqual([
      "pve1/local",
      "pve2/local",
      "pve1/local-lvm",
      "pve1/nas-backup",
      "pve2/nas-backup",
    ]);
  });

  it("reads usage, status, tags, templates and HA state", () => {
    const web = r.guests.find((g) => g.vmid === 100);
    expect(web).toMatchObject({
      type: "qemu",
      name: "web-01",
      node: "pve1",
      status: "running",
      cpus: 2,
      template: false,
      tags: ["prod", "web"],
      pool: "production",
      haState: "started",
    });
    expect(web?.maxMem).toBe(2 * 1024 ** 3);
    expect(r.guests.find((g) => g.vmid === 9000)?.template).toBe(true);
    expect(r.guests.find((g) => g.vmid === 103)?.status).toBe("other");
    expect(r.guests.find((g) => g.vmid === 102)?.status).toBe("stopped");
  });

  it("drops entries with hostile ids and cleans names and tags", () => {
    expect(r.guests.some((g) => g.name === "traversal" || g.name === "bad-node")).toBe(false);
    expect(r.dropped).toBeGreaterThanOrEqual(2);
    const hostile = r.guests.find((g) => g.vmid === 202);
    // Markup stays plain text (the web app escapes it); control characters and bidi overrides are gone.
    expect(hostile?.name).toBe("<img src=x onerror=alert(1)>evil");
    expect(hostile?.tags).toEqual(["ok", "a", "b"]);
  });

  it("reads PVE 9 answers with numbers as strings and unknown fields", () => {
    const n = parseResources(fixture("pve9", "cluster-resources"));
    expect(n.nodes[0]).toMatchObject({ name: "pve1", cpus: 16, maxMem: 68719476736, uptime: 100000 });
    const app = n.guests.find((g) => g.vmid === 100);
    expect(app).toMatchObject({ name: "app-01", tags: ["a", "b", "c"], template: false });
    expect(n.guests.find((g) => g.vmid === 101)).toMatchObject({ status: "paused", template: true });
    expect(n.storages[0]).toMatchObject({
      name: "local",
      content: ["backup", "iso"],
      used: 1000,
      total: 2000,
    });
  });

  it("copes with garbage", () => {
    for (const bad of [null, "x", 5, {}, [null, 1, "a", []], { data: [] }]) {
      const out = parseResources(bad);
      expect(out.guests).toEqual([]);
    }
  });

  it("keeps the first of two guests with the same id and truncates a huge list", () => {
    const dup = parseResources([
      { type: "qemu", vmid: 5, node: "pve1", name: "first", status: "running" },
      { type: "lxc", vmid: 5, node: "pve2", name: "second", status: "running" },
    ]);
    expect(dup.guests.map((g) => g.name)).toEqual(["first"]);
    const many = parseResources(
      Array.from({ length: 2100 }, (_, i) => ({
        type: "qemu",
        vmid: i + 1,
        node: "pve1",
        status: "running",
      })),
    );
    expect(many.guests).toHaveLength(2000);
    expect(many.guestsTruncated).toBe(true);
  });
});

describe("node status and updates", () => {
  it("reads usage, version and kernel", () => {
    expect(parseNodeStatus(fixture("pve8", "node-status-pve1"))).toEqual({
      cpu: 0.0421,
      cpus: 8,
      mem: 9 * 1024 ** 3,
      maxMem: 32 * 1024 ** 3,
      rootUsed: 14 * 1024 ** 3,
      rootTotal: 98 * 1024 ** 3,
      uptime: 2592000,
      pveVersion: "8.2.4",
      kernel: "6.8.12-1-pve",
    });
    expect(parseNodeStatus(fixture("pve9", "node-status-pve1"))).toMatchObject({
      pveVersion: "9.0.3",
      kernel: "6.14.8-2-pve",
    });
    expect(parseNodeStatus("nope")).toBeNull();
  });

  it("counts the upgradable packages of the node's own cache", () => {
    expect(parseAptUpdates(fixture("pve8", "apt-update-pve1"))).toBe(3);
    expect(parseAptUpdates(fixture("pve8", "apt-update-pve2"))).toBe(0);
    expect(parseAptUpdates({ not: "a list" })).toBeNull();
  });
});

describe("HA and backups", () => {
  it("reads HA states by guest id", () => {
    expect(parseHaResources(fixture("pve8", "ha-resources"))).toEqual(new Map([[100, "started"]]));
    expect(
      parseHaResources([
        { sid: "ct:200", state: "stopped" },
        { sid: "node:x", state: "started" },
        { sid: "vm:abc" },
      ]),
    ).toEqual(new Map([[200, "stopped"]]));
  });

  it("works out which guests a backup job includes", () => {
    const jobs = parseBackupJobs(fixture("pve8", "backup-jobs"));
    expect(jobs).toHaveLength(3);
    const covered = (vmid: number, pool: string | null = null) => coveredByBackupJob(jobs, { vmid, pool });
    expect(covered(100)).toBe(true); // listed
    expect(covered(200)).toBe(true); // listed
    expect(covered(555, "production")).toBe(true); // by pool
    expect(covered(555)).toBe(false); // the job that covers "all" is disabled
    const nine = parseBackupJobs(fixture("pve9", "backup-jobs"));
    expect(coveredByBackupJob(nine, { vmid: 100, pool: null })).toBe(true);
    expect(coveredByBackupJob(nine, { vmid: 101, pool: null })).toBe(false); // excluded
  });

  it("finds the newest backup of each guest and ignores broken entries", () => {
    const content = parseBackupContent(fixture("pve8", "storage-content-backup-nas"));
    expect(content.get(100)?.toISOString()).toBe("2026-10-20T02:00:05.000Z");
    expect(content.get(101)?.toISOString()).toBe("2026-10-01T02:00:05.000Z");
    expect(content.size).toBe(2);
  });
});

describe("guest details", () => {
  it("reads a few fields of the configuration and nothing else", () => {
    const config = parseGuestConfig(fixture("pve8", "qemu-100-config"));
    expect(config).toEqual({ ostype: "l26", template: null, agent: true, ips: ["192.0.2.50"] });
    // The description (markup), the cloud-init password and the SSH key are not part of the result.
    expect(JSON.stringify(config)).not.toMatch(/owned|hunter2|cipassword|ssh-ed25519|\*{4}/);
  });

  it("knows the agent switch in both spellings", () => {
    expect(parseGuestConfig(fixture("pve8", "qemu-101-config"))?.agent).toBe(true);
    expect(parseGuestConfig(fixture("pve8", "qemu-102-config"))?.agent).toBe(false);
    expect(parseGuestConfig(fixture("pve8", "qemu-102-config"))?.ostype).toBe("win10");
    expect(parseGuestConfig(fixture("pve8", "qemu-9000-config"))?.template).toBe(true);
  });

  it("reads static container addresses and ignores dhcp", () => {
    expect(parseGuestConfig(fixture("pve8", "lxc-200-config"))?.ips).toEqual(["192.0.2.60"]);
    expect(parseGuestConfig(fixture("pve8", "lxc-201-config"))?.ips).toEqual([]);
    expect(parseGuestConfig(fixture("pve8", "lxc-201-config"))?.ostype).toBe("alpine");
    expect(parseGuestConfig("x")).toBeNull();
  });

  it("takes addresses from the guest agent without loopback and link-local ones", () => {
    expect(parseAgentInterfaces(fixture("pve8", "qemu-agent-interfaces-100"))).toEqual([
      "192.0.2.50",
      "2001:db8::50",
    ]);
    expect(parseAgentInterfaces({ result: "x" })).toEqual([]);
  });

  it("takes addresses from the container's interfaces", () => {
    expect(parseLxcInterfaces(fixture("pve8", "lxc-interfaces-200"))).toEqual(["192.0.2.60", "2001:db8::60"]);
  });

  it("keeps at most eight addresses, IPv4 first, never a forbidden or invalid one", () => {
    const many = [
      "2001:db8::1",
      ...Array.from({ length: 10 }, (_, i) => `192.0.2.${i + 1}`),
      "127.0.0.1",
      "169.254.1.1",
      "ff02::1",
      "not-an-ip",
      "192.0.2.1",
    ];
    const clean = cleanAddresses(many);
    expect(clean).toHaveLength(8);
    expect(clean[0]).toBe("192.0.2.1");
    expect(clean.every((a) => !a.startsWith("127.") && !a.startsWith("169.254") && !a.includes("ff02"))).toBe(
      true,
    );
  });

  it("counts snapshots, finds the oldest and newest, and skips the 'current' marker", () => {
    const s = parseSnapshots(fixture("pve8", "qemu-100-snapshot"));
    expect(s?.count).toBe(2);
    expect(s?.newest?.toISOString()).toBe("2026-10-18T08:00:00.000Z");
    expect(s?.oldest?.toISOString()).toBe("2026-08-01T08:00:00.000Z");
    expect(parseSnapshots(fixture("pve8", "qemu-101-snapshot"))).toEqual({
      count: 0,
      newest: null,
      oldest: null,
    });
    expect(parseSnapshots({})).toBeNull();
  });

  it("splits tags the way Proxmox versions write them", () => {
    expect(parseTags("a;b;c")).toEqual(["a", "b", "c"]);
    expect(parseTags("a,b c;a")).toEqual(["a", "b", "c"]);
    expect(parseTags("<b>;ok;-x")).toEqual(["ok"]);
    expect(parseTags(undefined)).toEqual([]);
    expect(parseTags(Array.from({ length: 30 }, (_, i) => `t${i}`).join(";"))).toHaveLength(20);
  });
});

describe("token privileges", () => {
  it("accepts a token that can only audit", () => {
    expect(extraPrivileges(fixture("pve8", "permissions"))).toEqual([]);
    expect(extraPrivileges(fixture("pve9", "permissions"))).toEqual([]);
    expect(hasAnyPrivilege(fixture("pve8", "permissions"))).toBe(true);
  });

  it("lists everything beyond the audit privileges", () => {
    expect(extraPrivileges(fixture("pve8", "permissions-extra"))).toEqual([
      "Datastore.Allocate",
      "Permissions.Modify",
      "VM.PowerMgmt",
    ]);
  });

  it("does not take a look-alike for an audit privilege", () => {
    expect(
      extraPrivileges({ "/": { "Sys.Audit.Modify": 1, Audit: 1, "VM.Audit ": 1, "Sys.Modify": 1 } }),
    ).toEqual(["Audit", "Sys.Audit.Modify", "Sys.Modify"]);
  });

  it("reads empty or malformed answers as no privileges at all", () => {
    expect(extraPrivileges(null)).toEqual([]);
    expect(extraPrivileges([])).toEqual([]);
    expect(hasAnyPrivilege({})).toBe(false);
    expect(hasAnyPrivilege({ "/": {} })).toBe(false);
  });

  it("needs every extra privilege acknowledged", () => {
    expect(privilegesAcknowledged([], [])).toBe(true);
    expect(privilegesAcknowledged(["VM.PowerMgmt"], [])).toBe(false);
    expect(privilegesAcknowledged(["VM.PowerMgmt"], ["VM.PowerMgmt", "Sys.Modify"])).toBe(true);
    expect(privilegesAcknowledged(["VM.PowerMgmt", "Sys.Console"], ["VM.PowerMgmt"])).toBe(false);
  });
});

describe("envelope", () => {
  it("needs the data member", () => {
    expect(unwrap({ data: [1] })).toEqual([1]);
    expect(() => unwrap({})).toThrow();
    expect(() => unwrap([])).toThrow();
    expect(() => unwrap(null)).toThrow();
  });
});

describe("stale and untracked guests", () => {
  const now = new Date("2026-10-21T12:00:00Z");
  const daysAgo = (n: number) => new Date(now.getTime() - n * 86_400_000);
  const base: GuestFlagInput = {
    status: "running",
    template: false,
    statusSince: daysAgo(100),
    lastBackupAt: daysAgo(1),
    oldestSnapshotAt: null,
    backupsReadable: true,
    linked: true,
  };

  it("has documented thresholds", () => {
    expect([STALE_STOPPED_DAYS, STALE_BACKUP_DAYS, STALE_SNAPSHOT_DAYS]).toEqual([30, 7, 30]);
    expect(GUEST_FLAGS).toEqual(["stoppedLong", "noRecentBackup", "oldSnapshot", "untracked"]);
  });

  it("flags nothing for a healthy, linked guest", () => {
    expect(guestFlags(base, now)).toEqual([]);
  });

  it("flags a guest stopped for more than 30 days", () => {
    expect(guestFlags({ ...base, status: "stopped", statusSince: daysAgo(31) }, now)).toEqual([
      "stoppedLong",
    ]);
    expect(guestFlags({ ...base, status: "stopped", statusSince: daysAgo(30) }, now)).toEqual([]);
    expect(guestFlags({ ...base, status: "stopped", statusSince: daysAgo(30.01) }, now)).toEqual([
      "stoppedLong",
    ]);
    expect(guestFlags({ ...base, status: "paused", statusSince: daysAgo(90) }, now)).toEqual([]);
  });

  it("flags a missing or old backup, but only if backups can be read", () => {
    expect(guestFlags({ ...base, lastBackupAt: null }, now)).toEqual(["noRecentBackup"]);
    expect(guestFlags({ ...base, lastBackupAt: daysAgo(7.5) }, now)).toEqual(["noRecentBackup"]);
    expect(guestFlags({ ...base, lastBackupAt: daysAgo(7) }, now)).toEqual([]);
    expect(guestFlags({ ...base, lastBackupAt: null, backupsReadable: false }, now)).toEqual([]);
  });

  it("flags a snapshot older than 30 days", () => {
    expect(guestFlags({ ...base, oldestSnapshotAt: daysAgo(31) }, now)).toEqual(["oldSnapshot"]);
    expect(guestFlags({ ...base, oldestSnapshotAt: daysAgo(30) }, now)).toEqual([]);
  });

  it("flags a running guest without a linked server", () => {
    expect(guestFlags({ ...base, linked: false }, now)).toEqual(["untracked"]);
    expect(guestFlags({ ...base, linked: false, status: "stopped", statusSince: daysAgo(1) }, now)).toEqual(
      [],
    );
  });

  it("can flag several things at once, in a fixed order", () => {
    expect(
      guestFlags({ ...base, lastBackupAt: null, oldestSnapshotAt: daysAgo(90), linked: false }, now),
    ).toEqual(["noRecentBackup", "oldSnapshot", "untracked"]);
  });

  it("never flags a template", () => {
    expect(
      guestFlags(
        {
          ...base,
          template: true,
          status: "stopped",
          lastBackupAt: null,
          oldestSnapshotAt: daysAgo(90),
          linked: false,
        },
        now,
      ),
    ).toEqual([]);
  });
});

describe("source reference", () => {
  it("links a server to a guest as cluster:vmid", () => {
    const ref = proxmoxSourceRef("pxc_abcdefghij0123456789", 100);
    expect(ref).toBe("pxc_abcdefghij0123456789:100");
    expect(parseProxmoxSourceRef(ref)).toEqual({ clusterId: "pxc_abcdefghij0123456789", vmid: 100 });
    for (const bad of [
      "",
      "pxc_x:1",
      "pxc_abcdefghij0123456789:0",
      "pxc_abcdefghij0123456789:1:2",
      "host_abcdefghij0123456789:1",
    ]) {
      expect(parseProxmoxSourceRef(bad), bad).toBeNull();
    }
  });
});

describe("stored error texts", () => {
  it("map back to their code", () => {
    expect(parseProxmoxError(proxmoxErrorMessage("certificateChanged"))?.code).toBe("certificateChanged");
    expect(parseProxmoxError(proxmoxErrorMessage("syncTimeout", { minutes: 10 }))).toEqual({
      code: "syncTimeout",
      params: { minutes: "10" },
    });
    expect(parseProxmoxError("something else")).toBeNull();
  });
});
