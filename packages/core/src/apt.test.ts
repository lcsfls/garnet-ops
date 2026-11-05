import { describe, expect, it } from "vitest";
import { inventorySchema } from "./agent.ts";
import {
  type AptFacts,
  type AptSource,
  aptHints,
  classifyFinding,
  patchSummary,
  securitySourcesLine,
  thirdPartyPackages,
  thirdPartyPhp,
  upgradeCommand,
} from "./apt.ts";
import type { EolCycle } from "./eol-data.ts";

const NOW = new Date("2026-11-05T12:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

const source = (over: Partial<AptSource> & Pick<AptSource, "id" | "suite">): AptSource => ({
  host: "mirror.example.lan",
  path: "ubuntu",
  components: ["main", "universe"],
  origin: "Ubuntu",
  label: "Ubuntu",
  codename: "noble",
  date: daysAgo(0),
  fetchedAt: daysAgo(0),
  ...over,
});

function facts(over: Partial<AptFacts> = {}): AptFacts {
  return {
    listsUpdatedAt: daysAgo(0),
    arch: "amd64",
    sources: [
      source({ id: 0, suite: "noble" }),
      source({ id: 1, suite: "noble-updates" }),
      source({ id: 2, suite: "noble-security" }),
      source({
        id: 3,
        host: "ppa.launchpadcontent.net",
        path: "ondrej/php/ubuntu",
        suite: "noble",
        components: ["main"],
        origin: "LP-PPA-ondrej-php",
        label: "PPA for PHP",
      }),
    ],
    packages: [
      {
        name: "libssl3t64",
        arch: "amd64",
        installed: "3.0.13-0ubuntu3.4",
        from: [0],
        offers: [
          { source: 1, version: "3.0.13-0ubuntu3.5" },
          { source: 2, version: "3.0.13-0ubuntu3.5" },
        ],
      },
      {
        name: "php8.3-cli",
        arch: "amd64",
        installed: "8.3.13-1+ubuntu24.04.1+deb.sury.org+1",
        from: [3],
        offers: [{ source: 3, version: "8.3.14-1+ubuntu24.04.1+deb.sury.org+1" }],
      },
      {
        name: "php8.3",
        arch: "all",
        installed: "8.3.13-1+ubuntu24.04.1+deb.sury.org+1",
        from: [3],
        offers: [],
      },
      {
        name: "php7.4-fpm",
        arch: "amd64",
        installed: "1:7.4.33-18+ubuntu24.04.1+deb.sury.org+1",
        from: [3],
        offers: [],
      },
    ],
    ...over,
  };
}

const finding = (
  packageName: string,
  packageVersion: string,
  fixedIn: string[] | null,
  fixState = "fixed",
) => ({
  packageName,
  packageVersion,
  fixedIn,
  fixState,
});

describe("what can be patched now", () => {
  it("is patchable now when a configured source offers the fixed version or a newer one", () => {
    expect(
      classifyFinding(finding("libssl3t64", "3.0.13-0ubuntu3.4", ["3.0.13-0ubuntu3.5"]), facts(), NOW),
    ).toEqual({
      state: "patchable-now",
      fixedIn: "3.0.13-0ubuntu3.5",
      offered: { version: "3.0.13-0ubuntu3.5", source: 1 },
    });
    // Debian's order, not text order: 3.10 is newer than 3.5.
    const newer = facts({
      packages: [
        {
          name: "libssl3t64",
          arch: "amd64",
          installed: "3.0.13-0ubuntu3.4",
          from: [0],
          offers: [{ source: 2, version: "3.0.13-0ubuntu3.10" }],
        },
      ],
    });
    expect(
      classifyFinding(finding("libssl3t64", "3.0.13-0ubuntu3.4", ["3.0.13-0ubuntu3.5"]), newer, NOW).state,
    ).toBe("patchable-now");
  });

  it("waits for the mirror when the fresh lists do not offer the fix yet", () => {
    const verdict = classifyFinding(
      finding("libssl3t64", "3.0.13-0ubuntu3.4", ["3.0.13-0ubuntu3.6"]),
      facts(),
      NOW,
    );
    expect(verdict).toEqual({
      state: "waiting-for-mirror",
      fixedIn: "3.0.13-0ubuntu3.6",
      offered: { version: "3.0.13-0ubuntu3.5", source: 1 },
    });
    // A package nobody offers anything newer for is not in the facts at all.
    expect(
      classifyFinding(finding("bash", "5.2.21-2ubuntu4", ["5.2.21-2ubuntu4.1"]), facts(), NOW),
    ).toMatchObject({
      state: "waiting-for-mirror",
      offered: null,
    });
  });

  it("says the lists are stale when apt update has not run for three days", () => {
    const old = facts({ listsUpdatedAt: daysAgo(9) });
    expect(classifyFinding(finding("bash", "5.2.21-2ubuntu4", ["5.2.21-2ubuntu4.1"]), old, NOW).state).toBe(
      "lists-stale",
    );
    // What is offered already is still patchable now.
    expect(
      classifyFinding(finding("libssl3t64", "3.0.13-0ubuntu3.4", ["3.0.13-0ubuntu3.5"]), old, NOW).state,
    ).toBe("patchable-now");
    expect(patchSummary([], old, NOW)).toMatchObject({ listsAgeDays: 9, listsStale: true });
  });

  it("names Ubuntu Pro when the fix exists only as an ESM build and no ESM source is configured", () => {
    const esm = finding("libxml2", "2.9.14+dfsg-1.3ubuntu3", ["2.9.14+dfsg-1.3ubuntu3+esm1"]);
    expect(classifyFinding(esm, facts(), NOW).state).toBe("pro-only");
    const withPro = facts();
    withPro.sources.push(
      source({
        id: 9,
        host: "esm.ubuntu.com",
        path: "apps/ubuntu",
        suite: "noble-apps-security",
        origin: "UbuntuESMApps",
      }),
    );
    expect(classifyFinding(esm, withPro, NOW).state).toBe("waiting-for-mirror");
  });

  it("has no fix when the distribution has none, and knows nothing without facts", () => {
    expect(classifyFinding(finding("bash", "5.2", null, "not-fixed"), facts(), NOW).state).toBe("no-fix-yet");
    expect(classifyFinding(finding("bash", "5.2", ["5.1"]), facts(), NOW).state).toBe("no-fix-yet");
    expect(classifyFinding(finding("bash", "5.2", ["5.3"]), null, NOW).state).toBe("unknown");
  });

  it("sums up and names the command, with valid package names only", () => {
    const items = [
      finding("libssl3t64", "3.0.13-0ubuntu3.4", ["3.0.13-0ubuntu3.5"]),
      finding("libssl3t64", "3.0.13-0ubuntu3.4", ["3.0.13-0ubuntu3.5"]),
      finding("bash", "5.2.21-2ubuntu4", ["5.2.21-2ubuntu4.1"]),
    ].map((f) => ({ ...f, verdict: classifyFinding(f, facts(), NOW) }));
    expect(patchSummary(items, facts(), NOW)).toEqual({
      counts: {
        "patchable-now": 2,
        "waiting-for-mirror": 1,
        "lists-stale": 0,
        "pro-only": 0,
        "no-fix-yet": 0,
        unknown: 0,
      },
      listsAgeDays: 0,
      listsStale: false,
      command: "sudo apt install --only-upgrade libssl3t64",
    });
    expect(upgradeCommand(["php8.3", "x; rm -rf /", "Bad", "libc6"])).toBe(
      "sudo apt install --only-upgrade libc6 php8.3",
    );
    expect(upgradeCommand([])).toBeNull();
  });
});

describe("where security updates come from", () => {
  it("recommends the security server when a mirror serves the security pocket and a fix waits for it", () => {
    expect(aptHints(facts(), 1)).toEqual([
      {
        kind: "securityFromMirror",
        host: "mirror.example.lan",
        suite: "noble-security",
        lagDays: 0,
        line: "deb http://security.ubuntu.com/ubuntu noble-security main universe",
      },
    ]);
    expect(aptHints(facts(), 0)).toEqual([]);
    // A security index much older than the last apt update: the mirror lags even with nothing waiting.
    const lagging = facts();
    (lagging.sources[2] as AptSource).date = daysAgo(5);
    expect(aptHints(lagging, 0)).toMatchObject([{ kind: "securityFromMirror", lagDays: 5 }]);
  });

  it("says nothing when the security pocket comes from the security server itself", () => {
    const direct = facts();
    (direct.sources[2] as AptSource).host = "security.ubuntu.com";
    expect(aptHints(direct, 3)).toEqual([]);
  });

  it("asks for a security pocket when there is none, for Debian and for Ubuntu on arm64", () => {
    const debian = facts({
      arch: "amd64",
      sources: [
        source({
          id: 0,
          suite: "bookworm",
          host: "ftp.example.lan",
          path: "debian",
          origin: "Debian",
          codename: "bookworm",
          components: ["main", "contrib"],
        }),
      ],
      packages: [],
    });
    expect(aptHints(debian, 0)).toEqual([
      {
        kind: "noSecuritySource",
        line: "deb http://deb.debian.org/debian-security bookworm-security main contrib",
      },
    ]);
    const arm = facts({ arch: "arm64", sources: [source({ id: 0, suite: "noble" })] });
    expect(securitySourcesLine(arm)).toBe(
      "deb http://ports.ubuntu.com/ubuntu-ports noble-security main universe",
    );
    // Debian's security index calls its release "bookworm-security".
    const debSec = facts({
      sources: [
        source({
          id: 0,
          suite: "bookworm-security",
          host: "mirror.example.lan",
          path: "debian-security",
          origin: "Debian",
          codename: "bookworm-security",
          components: ["main"],
        }),
      ],
    });
    expect(aptHints(debSec, 2)).toMatchObject([
      { line: "deb http://deb.debian.org/debian-security bookworm-security main" },
    ]);
  });
});

describe("third-party packages", () => {
  const data: Record<string, EolCycle[]> = {
    php: [
      { cycle: "8.3", eol: "2027-12-31", latest: "8.3.14" },
      { cycle: "7.4", eol: "2022-11-28", latest: "7.4.33" },
    ],
  };

  it("lists packages only a source outside the distribution offers, per origin", () => {
    expect(thirdPartyPackages(facts())).toEqual([
      {
        origin: "LP-PPA-ondrej-php",
        host: "ppa.launchpadcontent.net",
        packages: [
          { name: "php7.4-fpm", installed: "1:7.4.33-18+ubuntu24.04.1+deb.sury.org+1" },
          { name: "php8.3", installed: "8.3.13-1+ubuntu24.04.1+deb.sury.org+1" },
          { name: "php8.3-cli", installed: "8.3.13-1+ubuntu24.04.1+deb.sury.org+1" },
        ],
      },
    ]);
    expect(thirdPartyPackages(null)).toEqual([]);
  });

  it("judges PHP from such a source by its upstream version, like the website rules", () => {
    expect(thirdPartyPhp(thirdPartyPackages(facts()), NOW, data as never)).toEqual([
      {
        version: "8.3.13",
        status: "outdated",
        cycle: "8.3",
        eol: "2027-12-31",
        latest: "8.3.14",
        severity: "medium",
        packages: ["php8.3", "php8.3-cli"],
      },
      {
        version: "7.4.33",
        status: "endOfLife",
        cycle: "7.4",
        eol: "2022-11-28",
        latest: "7.4.33",
        severity: "high",
        packages: ["php7.4-fpm"],
      },
    ]);
  });
});

describe("the apt facts in an inventory", () => {
  const base = { hostname: "web-01.example.lan", agentVersion: "0.1.0", containers: [], images: [] };

  it("takes them bounded and cleaned", () => {
    const parsed = inventorySchema.parse({
      ...base,
      apt: {
        listsUpdatedAt: "2026-11-05T10:00:00Z",
        arch: "amd64",
        sources: [
          {
            id: 0,
            host: "Mirror.Example.LAN",
            path: "ubuntu",
            suite: "noble\u001b[31m",
            components: ["main"],
            origin: "Ubuntu",
            date: "nonsense",
          },
        ],
        packages: [
          { name: "bash", arch: "amd64", installed: "5.2", offers: [{ source: 0, version: "5.3" }] },
        ],
      },
    });
    expect(parsed.apt?.sources[0]).toMatchObject({
      host: "mirror.example.lan",
      suite: "noble [31m",
      date: null,
      label: null,
    });
    expect(parsed.apt?.packages[0]).toMatchObject({ from: [], offers: [{ source: 0, version: "5.3" }] });
  });

  it("drops a report that does not fit, never the inventory, and works without one", () => {
    const bad = inventorySchema.parse({
      ...base,
      apt: { sources: [{ id: 0, host: "a b/../c" }], packages: [] },
    });
    expect(bad.apt).toBeUndefined();
    const huge = inventorySchema.parse({
      ...base,
      apt: {
        sources: [],
        packages: Array.from({ length: 5001 }, () => ({ name: "a", arch: "all", installed: "1" })),
      },
    });
    expect(huge.apt).toBeUndefined();
    expect(inventorySchema.parse(base).apt).toBeUndefined();
  });
});
