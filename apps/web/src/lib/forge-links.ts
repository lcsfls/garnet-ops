/**
 * Links into a forge for a repository address, so a wizard can point at the exact page instead of describing it. Only for a
 * plain `owner/name` path on an https or ssh address; anything else (subgroups, other hosts' layouts) gets no link.
 */
export interface ForgeRepo {
  /** https://host[:port] */
  base: string;
  owner: string;
  name: string;
  kind: "github" | "gitea-or-forgejo";
}

export function forgeRepo(url: string): ForgeRepo | null {
  let host: string;
  let path: string;
  const ssh = /^(?:ssh:\/\/)?[\w.-]+@([\w.-]+)(?::\d+)?[:/](.+)$/.exec(url);
  if (ssh?.[1] && ssh[2] && !url.startsWith("http")) {
    host = ssh[1];
    path = ssh[2];
  } else {
    try {
      const u = new URL(url);
      if (u.protocol !== "https:" && u.protocol !== "http:") return null;
      host = u.host;
      path = u.pathname;
    } catch {
      return null;
    }
  }
  const parts = path
    .replace(/^\/+|\/+$/g, "")
    .replace(/\.git$/, "")
    .split("/");
  if (parts.length !== 2 || !parts.every((p) => /^[\w.-]+$/.test(p))) return null;
  const [owner, name] = parts as [string, string];
  return {
    base: `https://${host}`,
    owner,
    name,
    kind: host === "github.com" ? "github" : "gitea-or-forgejo",
  };
}

/** Where the CI secret is added. */
export function secretsUrl(repo: ForgeRepo): string {
  const r = `${repo.base}/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}`;
  return repo.kind === "github" ? `${r}/settings/secrets/actions/new` : `${r}/settings/actions/secrets`;
}

/** GitHub only: the "new file" page with name and content filled in, on the given branch. */
export function newFileUrl(
  repo: ForgeRepo,
  branch: string,
  filename: string,
  content: string,
): string | null {
  if (repo.kind !== "github") return null;
  const q = new URLSearchParams({ filename, value: content });
  return `${repo.base}/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/new/${encodeURIComponent(branch)}?${q}`;
}
