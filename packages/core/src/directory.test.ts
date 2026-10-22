import { describe, expect, test } from "vitest";
import {
  AD_CHAIN_RULE,
  caCertificateProblem,
  checkDirectorySettings,
  checkPassword,
  checkServerUrl,
  checkUsername,
  DIRECTORY_LIMITS,
  DIRECTORY_PRESET_VALUES,
  type DirectorySettings,
  escapeFilterValue,
  filterTemplateProblem,
  type GroupRole,
  isUnderDn,
  isValidFilter,
  matchedGroups,
  normalizeDn,
  parseDn,
  readEmail,
  readText,
  readUniqueId,
  renderFilter,
  roleForGroups,
  sameDn,
} from "./directory.ts";
import { directoryHostPolicy } from "./directory-policy.ts";

describe("filter escaping (RFC 4515)", () => {
  test("escapes every character that has a meaning in a filter", () => {
    expect(escapeFilterValue("a*b(c)d\\e")).toBe("a\\2ab\\28c\\29d\\5ce");
    expect(escapeFilterValue("nul\u0000byte")).toBe("nul\\00byte");
    expect(escapeFilterValue("tab\there\nnewline\u007f")).toBe("tab\\09here\\0anewline\\7f");
  });

  test("leaves ordinary text and non-ASCII letters alone", () => {
    expect(escapeFilterValue("jdoe")).toBe("jdoe");
    expect(escapeFilterValue("j.doe@example.lan")).toBe("j.doe@example.lan");
    expect(escapeFilterValue("Jürgen Ångström")).toBe("Jürgen Ångström");
  });

  test.each([
    "*",
    "*)(uid=*",
    "admin)(|(objectClass=*",
    "x)(&(objectClass=user)(memberOf=CN=Admins,DC=example,DC=lan",
    "\\2a",
    "a\u0000)(cn=*",
  ])("a hostile user name %j stays a single value", (name) => {
    const filter = renderFilter("(&(objectClass=user)(sAMAccountName={username}))", { username: name });
    // Still exactly two items inside the AND, whatever was typed.
    expect(isValidFilter(filter)).toBe(true);
    const items = filter.match(/\((?:[^()\\]|\\[0-9a-f]{2})*\)/g) ?? [];
    expect(items).toEqual(["(objectClass=user)", `(sAMAccountName=${escapeFilterValue(name)})`]);
  });

  test("a value that looks like a placeholder is not expanded again", () => {
    expect(renderFilter("(&(uid={username})(member={dn}))", { username: "{dn}", dn: "cn=a" })).toBe(
      "(&(uid=\\7bdn\\7d)(member=cn=a))".replace("\\7bdn\\7d", "{dn}"),
    );
  });

  test("a placeholder without a value is a bug, not input", () => {
    expect(() => renderFilter("(uid={username})", {})).toThrow();
  });
});

describe("filter templates", () => {
  const options = { allowed: ["username"], required: ["username"] };
  test("accepts the presets", () => {
    for (const preset of Object.values(DIRECTORY_PRESET_VALUES)) {
      if (preset.userFilter) expect(filterTemplateProblem(preset.userFilter, options)).toBeNull();
    }
    expect(
      filterTemplateProblem(DIRECTORY_PRESET_VALUES.openldap.groupFilter, {
        allowed: ["dn", "username"],
        required: ["dn"],
      }),
    ).toBeNull();
  });

  test.each([
    ["", "empty"],
    ["(uid=x)", "missingPlaceholder"],
    ["(uid={username}", "syntax"],
    ["uid={username}", "syntax"],
    ["(uid={username}))", "syntax"],
    ["(&{username})", "syntax"],
    ["(uid={user})", "placeholder"],
    ["(uid={username}{dn})", "placeholder"],
    ["(uid={username}\\)", "syntax"],
    ["(uid={username}\u0000)", "syntax"],
    ["(=x{username})", "syntax"],
  ])("refuses %j (%s)", (template, problem) => {
    expect(filterTemplateProblem(template, options)).toBe(problem);
  });

  test("accepts extensible matches and substrings", () => {
    expect(isValidFilter(`(member:${AD_CHAIN_RULE}:=cn=a\\2cb,dc=example,dc=lan)`)).toBe(true);
    expect(isValidFilter("(cn=jo*n*)")).toBe(true);
    expect(isValidFilter("(!(disabled=TRUE))")).toBe(true);
    expect(isValidFilter("(|(a=1)(b=2)(&(c=3)(d=4)))")).toBe(true);
  });

  test("refuses a filter deeper than the limit", () => {
    const deep = `${"(&".repeat(40)}(a=1)${")".repeat(40)}`;
    expect(isValidFilter(deep)).toBe(false);
  });

  test("a template longer than the limit is refused", () => {
    expect(filterTemplateProblem(`(uid={username}${"x".repeat(600)})`, options)).toBe("tooLong");
  });
});

describe("user name and password", () => {
  test.each([
    "jdoe",
    "j.doe",
    "j_doe-2",
    "jdoe@example.lan",
    "EXAMPLE\\jdoe",
    "o'brien",
    "Jürgen",
    "  jdoe  ",
  ])("accepts %j", (name) => {
    expect(checkUsername(name)).toBe(name.trim());
  });

  test.each([
    "",
    " ",
    "a b",
    "*",
    "jdoe)(uid=*",
    "a=b",
    "a,b",
    "a;b",
    "a\u0000b",
    "a\nb",
    ".hidden",
    "x".repeat(DIRECTORY_LIMITS.usernameMax + 1),
  ])("refuses %j", (name) => {
    expect(checkUsername(name)).toBeNull();
  });

  test("refuses things that are not strings", () => {
    expect(checkUsername(undefined)).toBeNull();
    expect(checkUsername(42)).toBeNull();
    expect(checkUsername({ toString: () => "jdoe" })).toBeNull();
  });

  test("an empty password never passes (unauthenticated bind)", () => {
    expect(checkPassword("")).toBeNull();
    expect(checkPassword(undefined)).toBeNull();
    expect(checkPassword("pass\u0000word")).toBeNull();
    expect(checkPassword("x".repeat(DIRECTORY_LIMITS.passwordMax + 1))).toBeNull();
    expect(checkPassword(" ")).toBe(" ");
    expect(checkPassword("correct horse battery staple")).toBe("correct horse battery staple");
  });
});

describe("distinguished names", () => {
  test("parses escapes, hex pairs and spacing", () => {
    expect(parseDn("CN=Smith\\, John,OU=Users,DC=example,DC=lan")).toEqual([
      [{ type: "cn", value: "Smith, John" }],
      [{ type: "ou", value: "Users" }],
      [{ type: "dc", value: "example" }],
      [{ type: "dc", value: "lan" }],
    ]);
    expect(parseDn("cn=caf\\C3\\A9,dc=example")?.[0]).toEqual([{ type: "cn", value: "café" }]);
    expect(parseDn("CN=a ,  OU=b")?.map((r) => r[0]?.value)).toEqual(["a", "b"]);
    expect(parseDn("cn=\\ lead\\ ,dc=x")?.[0]).toEqual([{ type: "cn", value: " lead " }]);
    expect(parseDn("")).toEqual([]);
  });

  test("sorts multi-valued RDNs", () => {
    expect(normalizeDn("uid=a+cn=b,dc=x")).toBe(normalizeDn("cn=b+uid=a,dc=x"));
  });

  test.each([
    "cn",
    "=x",
    "cn=a,",
    "cn=a\\",
    'cn="quoted",dc=x',
    "cn=a<b",
    "cn=a;b",
    "c n=a",
    "cn=\\zz",
    "cn=\\C3,dc=x", // truncated UTF-8
    "x".repeat(DIRECTORY_LIMITS.maxDnLength + 1),
  ])("refuses the malformed DN %j", (dn) => {
    expect(parseDn(dn)).toBeNull();
  });

  test("compares case-insensitively and ignores spelling of escapes", () => {
    expect(sameDn("CN=Admins,OU=Groups,DC=Example,DC=Lan", "cn=admins, ou=groups, dc=example, dc=lan")).toBe(
      true,
    );
    expect(sameDn("CN=Smith\\, John,DC=x", "cn=Smith\\2c John,dc=x")).toBe(true);
    expect(sameDn("CN=a,DC=x", "CN=b,DC=x")).toBe(false);
    expect(sameDn("CN=a,DC=x", "CN=a,DC=y")).toBe(false);
  });

  test("a comma in a value does not become a second RDN", () => {
    expect(sameDn("CN=Admins\\,OU=Evil,DC=x", "CN=Admins,OU=Evil,DC=x")).toBe(false);
  });

  test("invalid DNs match nothing, not even themselves", () => {
    expect(sameDn("cn=a\\", "cn=a\\")).toBe(false);
    expect(isUnderDn("cn=a\\", "dc=x")).toBe(false);
    expect(isUnderDn("cn=a,dc=x", "dc=")).toBe(false);
  });

  test("is-under checks the whole suffix", () => {
    const base = "OU=Users,DC=example,DC=lan";
    expect(isUnderDn("CN=Jo,OU=Users,DC=example,DC=lan", base)).toBe(true);
    expect(isUnderDn("CN=Jo,OU=Sub,OU=Users,DC=Example,DC=LAN", base)).toBe(true);
    expect(isUnderDn(base, base)).toBe(true);
    expect(isUnderDn("CN=Jo,OU=Users,DC=example,DC=com", base)).toBe(false);
    expect(isUnderDn("CN=Jo,OU=Other,DC=example,DC=lan", base)).toBe(false);
    // "OU=Users" must be an RDN, not the tail of one.
    expect(isUnderDn("CN=Jo,OU=EvilUsers,DC=example,DC=lan", base)).toBe(false);
    expect(isUnderDn("DC=lan", base)).toBe(false);
  });
});

describe("groups and roles", () => {
  const mappings = [
    { dn: "CN=GarnetOps-Admins,OU=Groups,DC=example,DC=lan", role: "admin" as const },
    { dn: "CN=GarnetOps-Users,OU=Groups,DC=example,DC=lan", role: "member" as const },
    { dn: "CN=GarnetOps-Viewers,OU=Groups,DC=example,DC=lan", role: "viewer" as const },
  ];

  test("the highest role wins", () => {
    expect(roleForGroups([mappings[2]?.dn ?? "", mappings[1]?.dn ?? ""], mappings)).toBe("member");
    expect(
      roleForGroups(
        mappings.map((m) => m.dn),
        mappings,
      ),
    ).toBe("admin");
    expect(roleForGroups([mappings[2]?.dn ?? ""], mappings)).toBe("viewer");
  });

  test("no allowed group means no role", () => {
    expect(roleForGroups([], mappings)).toBeNull();
    expect(roleForGroups(["CN=Domain Users,CN=Users,DC=example,DC=lan"], mappings)).toBeNull();
    expect(roleForGroups(["CN=GarnetOps-Admins,OU=Elsewhere,DC=example,DC=lan"], mappings)).toBeNull();
  });

  test("group names compare like DNs", () => {
    expect(roleForGroups(["cn=garnetops-admins,ou=groups,dc=EXAMPLE,dc=LAN"], mappings)).toBe("admin");
  });

  test("an unparseable group never grants a role, even one that equals the mapping text", () => {
    expect(roleForGroups(["cn=a\\"], [{ dn: "cn=a\\", role: "admin" }])).toBeNull();
  });

  test("a role can only be admin, member or viewer", () => {
    // Types forbid "owner"; at run time a stored (hand-edited) "owner" must not be honoured either.
    expect(roleForGroups(["cn=a,dc=x"], [{ dn: "cn=a,dc=x", role: "viewer" }])).toBe("viewer");
    const forged = { dn: "cn=a,dc=x", role: "owner" } as unknown as GroupRole;
    expect(roleForGroups(["cn=a,dc=x"], [forged])).toBeNull();
    expect(roleForGroups(["cn=a,dc=x"], [forged, { dn: "cn=a,dc=x", role: "viewer" }])).toBe("viewer");
  });

  test("lists the configured groups that matched", () => {
    expect(matchedGroups([mappings[1]?.dn.toLowerCase() ?? "", "cn=other,dc=x"], mappings)).toEqual([
      mappings[1]?.dn,
    ]);
  });
});

describe("the directory's unique id", () => {
  test("converts objectGUID to the usual text form", () => {
    const bytes = Uint8Array.from([
      0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ]);
    expect(readUniqueId("objectGUID", bytes)).toBe("12345678-9abc-def0-0123-456789abcdef");
    expect(readUniqueId("objectguid", [bytes])).toBe("12345678-9abc-def0-0123-456789abcdef");
  });

  test("reads text ids in lower case", () => {
    expect(readUniqueId("entryUUID", "0F0E0D0C-0B0A-0908-0706-050403020100")).toBe(
      "0f0e0d0c-0b0a-0908-0706-050403020100",
    );
    expect(readUniqueId("entryUUID", ["  abc "])).toBe("abc");
  });

  test("text handed over as bytes stays text; other binary values become hex; nothing usable becomes null", () => {
    expect(readUniqueId("entryUUID", Buffer.from("AAAAAAAA-0000-4000-8000-000000000001"))).toBe(
      "aaaaaaaa-0000-4000-8000-000000000001",
    );
    expect(readUniqueId("objectSid", Uint8Array.from([1, 2, 255]))).toBe("0102ff");
    expect(readUniqueId("objectSid", Uint8Array.from([1, 2, 3]))).toBe("010203");
    expect(readUniqueId("entryUUID", "")).toBeNull();
    expect(readUniqueId("entryUUID", undefined)).toBeNull();
    expect(readUniqueId("entryUUID", [])).toBeNull();
    expect(readUniqueId("entryUUID", 5)).toBeNull();
    expect(readUniqueId("entryUUID", "a\u0000b")).toBeNull();
    expect(readUniqueId("entryUUID", "x".repeat(129))).toBeNull();
    expect(readUniqueId("objectGUID", new Uint8Array(0))).toBeNull();
  });

  test("text and mail attributes are cleaned", () => {
    expect(readText(["  Jo\u0000hn  Doe ", "second"])).toBe("Jo hn  Doe");
    expect(readText("")).toBeNull();
    expect(readText(3)).toBeNull();
    expect(readEmail("Jo.Doe@Example.LAN")).toBe("jo.doe@example.lan");
    expect(readEmail(["jdoe@example.lan"])).toBe("jdoe@example.lan");
    for (const bad of [
      "jdoe",
      "jdoe@",
      "@example.lan",
      "a b@example.lan",
      "a@b",
      "<a@example.lan>",
      "a@b@c.lan",
    ]) {
      expect(readEmail(bad)).toBeNull();
    }
  });
});

describe("server URLs", () => {
  const ok = (url: string) => checkServerUrl(url, directoryHostPolicy);
  test("normalises ldaps and ldap, with default ports", () => {
    expect(ok("ldaps://dc1.example.lan")).toMatchObject({
      ok: true,
      url: "ldaps://dc1.example.lan",
      port: 636,
      scheme: "ldaps",
    });
    expect(ok("LDAPS://DC1.Example.LAN:636")).toMatchObject({
      ok: true,
      url: "ldaps://dc1.example.lan",
      port: 636,
    });
    expect(ok("ldaps://dc1.example.lan:3269")).toMatchObject({
      ok: true,
      url: "ldaps://dc1.example.lan:3269",
      port: 3269,
    });
    expect(ok("ldap://dc1.example.lan")).toMatchObject({
      ok: true,
      url: "ldap://dc1.example.lan",
      port: 389,
      scheme: "ldap",
    });
    expect(ok("ldaps://192.0.2.10")).toMatchObject({ ok: true, host: "192.0.2.10" });
    expect(ok("ldaps://[2001:db8::10]:636")).toMatchObject({
      ok: true,
      url: "ldaps://[2001:db8::10]",
      host: "2001:db8::10",
    });
  });

  test.each([
    ["http://dc1.example.lan", "scheme"],
    ["ldapi:///var/run/ldapi", "scheme"],
    ["dc1.example.lan", "syntax"],
    ["ldaps://user:pw@dc1.example.lan", "credentials"],
    ["ldaps://dc1.example.lan/dc=example", "path"],
    ["ldaps://dc1.example.lan?x=1", "path"],
    ["ldaps://dc1.example.lan:0", "port"],
    ["ldaps://dc1.example.lan:99999", "port"],
    ["ldaps://dc1.example.lan:abc", "port"],
    ["ldaps://127.0.0.1", "host"],
    ["ldaps://localhost", "host"],
    ["ldaps://169.254.169.254", "host"],
    ["ldaps://[::1]", "host"],
    ["ldaps://127.1", "host"],
    ["ldaps://", "path"],
  ])("refuses %j (%s)", (url, problem) => {
    expect(ok(url)).toEqual({ ok: false, problem });
  });
});

describe("CA certificates", () => {
  const block = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ2V4YW1wbGU=\n-----END CERTIFICATE-----";
  test("accepts one or more certificates", () => {
    expect(caCertificateProblem(block)).toBeNull();
    expect(caCertificateProblem(`${block}\n${block}\n`)).toBeNull();
  });
  test("refuses anything else", () => {
    // Fake key blocks, assembled so secret scanners do not mistake the test for a leaked key.
    const keyBlock = (label: string) =>
      ["-----BEGIN ", label, "-----\nabc\n-----END ", label, "-----"].join("");
    expect(caCertificateProblem("")).toBe("empty");
    expect(caCertificateProblem("hello")).toBe("syntax");
    expect(caCertificateProblem(`${block}\njunk`)).toBe("syntax");
    expect(caCertificateProblem(keyBlock("PRIVATE KEY"))).toBe("privateKey");
    expect(caCertificateProblem(`${block}\n${keyBlock("RSA PRIVATE KEY")}`)).toBe("privateKey");
    expect(caCertificateProblem("x".repeat(DIRECTORY_LIMITS.maxCaPemLength + 1))).toBe("tooLong");
  });
});

describe("settings", () => {
  const good: DirectorySettings = {
    enabled: false,
    preset: "active-directory",
    servers: ["ldaps://dc1.example.lan", "ldaps://dc2.example.lan:636"],
    tlsTrust: "system",
    caCertificate: "",
    bindDn: "CN=svc-garnetops,OU=Service,DC=example,DC=lan",
    userBaseDn: "OU=Users,DC=example,DC=lan",
    ...DIRECTORY_PRESET_VALUES["active-directory"],
    groupRoles: [
      { dn: "CN=GarnetOps-Admins,OU=Groups,DC=example,DC=lan", role: "admin" },
      { dn: "CN=GarnetOps-Users,OU=Groups,DC=example,DC=lan", role: "member" },
    ],
    emailVerified: false,
    connectTimeoutSeconds: 5,
    operationTimeoutSeconds: 10,
    sizeLimit: 50,
  };
  const check = (patch: Partial<DirectorySettings>) =>
    checkDirectorySettings({ ...good, ...patch }, directoryHostPolicy);

  test("accepts good settings and normalises the servers", () => {
    const result = check({});
    expect(result.problems).toEqual([]);
    expect(result.servers).toEqual(["ldaps://dc1.example.lan", "ldaps://dc2.example.lan"]);
  });

  test("accepts the OpenLDAP preset", () => {
    expect(
      check({
        ...DIRECTORY_PRESET_VALUES.openldap,
        preset: "openldap",
        bindDn: "cn=reader,dc=example,dc=lan",
        userBaseDn: "ou=people,dc=example,dc=lan",
      }).problems,
    ).toEqual([]);
  });

  test("reports each problem on its field", () => {
    const codes = (patch: Partial<DirectorySettings>) =>
      check(patch).problems.map((p) => `${p.field}:${p.code}`);
    expect(codes({ servers: [] })).toEqual(["servers:empty"]);
    expect(codes({ servers: ["http://dc"] })).toEqual(["servers.0:url_scheme"]);
    expect(codes({ servers: ["ldaps://dc1.example.lan", "LDAPS://dc1.example.lan:636"] })).toEqual([
      "servers.1:url_duplicate",
    ]);
    expect(codes({ servers: Array.from({ length: 5 }, (_, i) => `ldaps://dc${i}.example.lan`) })).toEqual([
      "servers:tooMany",
    ]);
    expect(codes({ tlsTrust: "ca", caCertificate: "" })).toEqual(["caCertificate:ca_empty"]);
    expect(codes({ bindDn: "" })).toEqual(["bindDn:dn_empty"]);
    expect(codes({ bindDn: "not a dn" })).toEqual(["bindDn:dn_invalid"]);
    expect(codes({ userBaseDn: "cn=a\\" })).toEqual(["userBaseDn:dn_invalid"]);
    expect(codes({ userFilter: "(sAMAccountName=jdoe)" })).toEqual(["userFilter:filter_missingPlaceholder"]);
    expect(codes({ userFilter: "(uid={username}" })).toEqual(["userFilter:filter_syntax"]);
    expect(codes({ emailAttribute: "ma il" })).toEqual(["emailAttribute:attribute_invalid"]);
    expect(codes({ uniqueIdAttribute: "" })).toEqual(["uniqueIdAttribute:attribute_invalid"]);
    expect(codes({ groupRoles: [] })).toEqual(["groupRoles:empty"]);
    expect(codes({ groupRoles: [{ dn: "x", role: "admin" }] })).toEqual(["groupRoles.0:dn_invalid"]);
    expect(
      codes({
        groupRoles: [
          { dn: "cn=a,dc=x", role: "admin" },
          { dn: "CN=A, DC=X", role: "viewer" },
        ],
      }),
    ).toEqual(["groupRoles.1:dn_duplicate"]);
    expect(codes({ groupRoles: [{ dn: "cn=a,dc=x", role: "owner" as never }] })).toEqual([
      "groupRoles.0:role_invalid",
    ]);
    expect(codes({ connectTimeoutSeconds: 0 })).toEqual(["connectTimeoutSeconds:range"]);
    expect(codes({ operationTimeoutSeconds: 61 })).toEqual(["operationTimeoutSeconds:range"]);
    expect(codes({ sizeLimit: 1 })).toEqual(["sizeLimit:range"]);
  });

  test("the group filter is only checked in search mode", () => {
    expect(check({ groupMode: "nested", groupFilter: "garbage" }).problems).toEqual([]);
    expect(check({ groupMode: "search", groupFilter: "(member=x)" }).problems.map((p) => p.code)).toEqual([
      "filter_missingPlaceholder",
    ]);
  });

  test("a loopback server is refused", () => {
    expect(check({ servers: ["ldaps://127.0.0.1"] }).problems).toEqual([
      { field: "servers.0", code: "url_host" },
    ]);
  });
});
