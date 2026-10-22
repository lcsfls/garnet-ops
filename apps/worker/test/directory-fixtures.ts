/**
 * Made-up directories for the tests of the directory sign-in (ADR 0020): one in the shape of
 * Active Directory and one in the shape of OpenLDAP. Domain `example.lan`, addresses at
 * `example.lan`, passwords that are obviously not real. Nothing here is a real person or system.
 */
import type { FakeEntry } from "./fake-ldap.ts";

export const SERVICE_PASSWORD = "test-only-service-password";
export const USER_PASSWORD = "test-only-user-password";
export const NEW_USER_PASSWORD = "test-only-other-password";

/** A 16-byte `objectGUID` for user number `n`, in Microsoft's byte order. */
export const guid = (n: number): Buffer =>
  Buffer.from([0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, n]);
/** The text form of {@link guid}. */
export const guidText = (n: number): string =>
  `12345678-9abc-def0-0123-456789abcd${n.toString(16).padStart(2, "0")}`;

const ROOT = "DC=example,DC=lan";
export const AD = {
  root: ROOT,
  usersOu: `OU=Users,${ROOT}`,
  groupsOu: `OU=Groups,${ROOT}`,
  service: `CN=svc-garnetops,OU=Service,${ROOT}`,
  admins: `CN=GarnetOps-Admins,OU=Groups,${ROOT}`,
  users: `CN=GarnetOps-Users,OU=Groups,${ROOT}`,
  viewers: `CN=GarnetOps-Viewers,OU=Groups,${ROOT}`,
  engineering: `CN=Engineering,OU=Groups,${ROOT}`,
  everyone: `CN=Everyone,OU=Groups,${ROOT}`,
  user: (cn: string) => `CN=${cn},OU=Users,${ROOT}`,
  /** A name with a comma and parentheses in it, escaped the way Active Directory writes it. */
  zed: `CN=Smith\\, Zed (Ops),OU=Users,${ROOT}`,
} as const;

function adUser(
  cn: string,
  sam: string,
  n: number,
  options: { mail?: string | null; memberOf?: string[]; displayName?: string; dn?: string } = {},
): FakeEntry {
  const mail = options.mail === undefined ? `${sam}@example.lan` : options.mail;
  return {
    dn: options.dn ?? AD.user(cn),
    attributes: {
      objectClass: ["top", "person", "organizationalPerson", "user"],
      cn: [cn],
      sAMAccountName: [sam],
      displayName: [options.displayName ?? cn],
      ...(mail ? { mail: [mail] } : {}),
      objectGUID: [guid(n)],
      memberOf: options.memberOf ?? [],
    },
  };
}

function group(dn: string, members: string[]): FakeEntry {
  return {
    dn,
    attributes: { objectClass: ["top", "group"], cn: [dn.split(",")[0]?.slice(3) ?? ""], member: members },
  };
}

/**
 * The Active Directory shaped data set:
 * - jdoe is in Engineering, which is a member of GarnetOps-Admins (admin only through the nested group);
 * - asmith is in GarnetOps-Users (member) and GarnetOps-Viewers (viewer): the higher role wins;
 * - bwilson is in GarnetOps-Viewers only;
 * - cnoone is in no allowed group;
 * - two entries share the account name `twin`; `nomail` has no mail attribute; `local-person` has the mail
 *   address of a local account the tests create.
 */
export function activeDirectory(): { entries: FakeEntry[]; passwords: Record<string, string> } {
  const entries: FakeEntry[] = [
    { dn: ROOT, attributes: { objectClass: ["top", "domain"], dc: ["example"] } },
    { dn: AD.usersOu, attributes: { objectClass: ["top", "organizationalUnit"], ou: ["Users"] } },
    { dn: AD.groupsOu, attributes: { objectClass: ["top", "organizationalUnit"], ou: ["Groups"] } },
    { dn: `OU=Service,${ROOT}`, attributes: { objectClass: ["top", "organizationalUnit"], ou: ["Service"] } },
    {
      dn: AD.service,
      attributes: {
        objectClass: ["top", "person", "user"],
        cn: ["svc-garnetops"],
        sAMAccountName: ["svc-garnetops"],
      },
    },
    adUser("John Doe", "jdoe", 1, { memberOf: [AD.engineering], displayName: "John Doe" }),
    adUser("Anna Smith", "asmith", 2, { memberOf: [AD.users, AD.viewers], displayName: "Anna Smith" }),
    adUser("Ben Wilson", "bwilson", 3, { memberOf: [AD.viewers] }),
    adUser("Cleo Noone", "cnoone", 4, { memberOf: [AD.everyone] }),
    adUser("Twin One", "twin", 5, { memberOf: [AD.users] }),
    adUser("Twin Two", "twin", 6, { memberOf: [AD.users] }),
    adUser("No Mail", "nomail", 7, { mail: null, memberOf: [AD.users] }),
    adUser("Local Person", "lperson", 8, { mail: "local.person@example.lan", memberOf: [AD.users] }),
    adUser("Smith, Zed (Ops)", "zsmith", 9, { memberOf: [AD.users], dn: AD.zed }),
    group(AD.admins, [AD.engineering]),
    group(AD.users, [
      AD.user("Anna Smith"),
      AD.user("Twin One"),
      AD.user("Twin Two"),
      AD.user("No Mail"),
      AD.user("Local Person"),
      AD.zed,
    ]),
    group(AD.viewers, [AD.user("Anna Smith"), AD.user("Ben Wilson")]),
    group(AD.engineering, [AD.user("John Doe")]),
    group(AD.everyone, [AD.user("Cleo Noone")]),
  ];
  const passwords: Record<string, string> = { [AD.service]: SERVICE_PASSWORD };
  for (const e of entries)
    if (e.dn.includes("OU=Users,") && e.attributes.sAMAccountName) passwords[e.dn] = USER_PASSWORD;
  return { entries, passwords };
}

export const ADMIN_GROUPS = [
  { dn: AD.admins, role: "admin" as const },
  { dn: AD.users, role: "member" as const },
  { dn: AD.viewers, role: "viewer" as const },
];

const OL_ROOT = "dc=example,dc=lan";
export const OPENLDAP = {
  root: OL_ROOT,
  peopleOu: `ou=people,${OL_ROOT}`,
  service: `cn=reader,${OL_ROOT}`,
  admins: `cn=garnetops-admins,ou=groups,${OL_ROOT}`,
  users: `cn=garnetops-users,ou=groups,${OL_ROOT}`,
  viewers: `cn=garnetops-viewers,ou=groups,${OL_ROOT}`,
  user: (uid: string) => `uid=${uid},ou=people,${OL_ROOT}`,
} as const;

/** The OpenLDAP shaped data set: `groupOfNames` groups with `member`, `entryUUID` as the unique id, no `memberOf`. */
export function openLdap(): { entries: FakeEntry[]; passwords: Record<string, string> } {
  const person = (uid: string, n: number): FakeEntry => ({
    dn: OPENLDAP.user(uid),
    attributes: {
      objectClass: ["top", "inetOrgPerson"],
      uid: [uid],
      cn: [`Person ${uid}`],
      sn: [uid],
      mail: [`${uid}@example.lan`],
      entryUUID: [`aaaaaaaa-0000-4000-8000-0000000000${n.toString(16).padStart(2, "0")}`.toUpperCase()],
    },
  });
  const entries: FakeEntry[] = [
    { dn: OL_ROOT, attributes: { objectClass: ["top", "dcObject"], dc: ["example"] } },
    { dn: OPENLDAP.peopleOu, attributes: { objectClass: ["top", "organizationalUnit"], ou: ["people"] } },
    {
      dn: `ou=groups,${OL_ROOT}`,
      attributes: { objectClass: ["top", "organizationalUnit"], ou: ["groups"] },
    },
    { dn: OPENLDAP.service, attributes: { objectClass: ["top", "organizationalRole"], cn: ["reader"] } },
    person("olga", 1),
    person("oskar", 2),
    person("omar", 3),
    {
      dn: OPENLDAP.admins,
      attributes: {
        objectClass: ["top", "groupOfNames"],
        cn: ["garnetops-admins"],
        member: [OPENLDAP.user("olga")],
      },
    },
    {
      dn: OPENLDAP.users,
      attributes: {
        objectClass: ["top", "groupOfNames"],
        cn: ["garnetops-users"],
        member: [OPENLDAP.user("oskar")],
      },
    },
    {
      dn: OPENLDAP.viewers,
      attributes: {
        objectClass: ["top", "groupOfNames"],
        cn: ["garnetops-viewers"],
        member: [OPENLDAP.user("oskar")],
      },
    },
  ];
  const passwords: Record<string, string> = { [OPENLDAP.service]: SERVICE_PASSWORD };
  for (const uid of ["olga", "oskar", "omar"]) passwords[OPENLDAP.user(uid)] = USER_PASSWORD;
  return { entries, passwords };
}
