/**
 * Debian package versions (`[epoch:]upstream[-revision]`) compared exactly as dpkg does (`dpkg --compare-versions`, deb-version(7)):
 * the epoch numerically, then upstream version and revision with dpkg's ordering, in which `~` sorts before everything, even the
 * end of the string ("1.0~rc1" < "1.0"), letters before other characters, and runs of digits numerically.
 */

export interface DebVersion {
  epoch: number;
  upstream: string;
  revision: string;
}

/** Splits a version into its parts; null for text that is not a version (empty, a bad epoch). */
export function parseDebVersion(text: string): DebVersion | null {
  const value = text.trim();
  if (!value || value.length > 300) return null;
  let epoch = 0;
  let rest = value;
  const colon = value.indexOf(":");
  if (colon !== -1) {
    const e = value.slice(0, colon);
    if (!/^\d{1,9}$/.test(e)) return null;
    epoch = Number(e);
    rest = value.slice(colon + 1);
  }
  const dash = rest.lastIndexOf("-");
  const upstream = dash === -1 ? rest : rest.slice(0, dash);
  const revision = dash === -1 ? "" : rest.slice(dash + 1);
  if (!upstream || !/^[0-9]/.test(upstream)) return null;
  return { epoch, upstream, revision };
}

const isDigit = (c: string | undefined) => c !== undefined && c >= "0" && c <= "9";
const isLetter = (c: string | undefined) =>
  c !== undefined && ((c >= "a" && c <= "z") || (c >= "A" && c <= "Z"));

/** dpkg's weight of a character outside a run of digits. */
function order(c: string | undefined): number {
  if (c === undefined || isDigit(c)) return 0;
  if (isLetter(c)) return c.charCodeAt(0);
  if (c === "~") return -1;
  return c.charCodeAt(0) + 256;
}

/** dpkg's `verrevcmp`: compares an upstream version or a revision. */
function compareFragment(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    let firstDiff = 0;
    while ((i < a.length && !isDigit(a[i])) || (j < b.length && !isDigit(b[j]))) {
      const ac = order(a[i]);
      const bc = order(b[j]);
      if (ac !== bc) return ac - bc;
      i++;
      j++;
    }
    while (a[i] === "0") i++;
    while (b[j] === "0") j++;
    while (isDigit(a[i]) && isDigit(b[j])) {
      if (!firstDiff) firstDiff = (a.charCodeAt(i) as number) - (b.charCodeAt(j) as number);
      i++;
      j++;
    }
    if (isDigit(a[i])) return 1;
    if (isDigit(b[j])) return -1;
    if (firstDiff) return firstDiff;
  }
  return 0;
}

/**
 * Compares two Debian versions: negative if `a` is older, positive if newer, 0 if equal. Text that is not a version sorts before
 * every version, so it never counts as "new enough".
 */
export function compareDebVersions(a: string, b: string): number {
  const x = parseDebVersion(a);
  const y = parseDebVersion(b);
  if (!x || !y) return (x ? 1 : 0) - (y ? 1 : 0);
  if (x.epoch !== y.epoch) return x.epoch - y.epoch;
  return compareFragment(x.upstream, y.upstream) || compareFragment(x.revision, y.revision);
}

/** The upstream version without epoch and revision: "1:8.3.14-1+ubuntu24.04.1+deb.sury.org+1" is "8.3.14". */
export function debUpstream(text: string): string | null {
  return parseDebVersion(text)?.upstream ?? null;
}
