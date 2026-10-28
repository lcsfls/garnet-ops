/** The forge a repository lives on, from its address; self-hosted forges show their host name. */
export function forgeOf(url: string): string {
  const host = (/^[a-z]+:\/\/(?:[^@/]+@)?([^/:]+)/i.exec(url) ??
    /^[^@]+@([^:]+):/.exec(url))?.[1]?.toLowerCase();
  if (!host) return url;
  const known: Record<string, string> = {
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "codeberg.org": "Codeberg",
    "bitbucket.org": "Bitbucket",
  };
  return known[host] ?? host;
}
