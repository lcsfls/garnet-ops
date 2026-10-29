#!/usr/bin/env node
/**
 * Writes the title and the text of a GitHub release from CHANGELOG.md, so a release never needs
 * editing by hand (a release created or published by hand blocks the release workflow).
 *
 *   node scripts/release-notes.mjs v0.0.10 <notes file>     prints the title, writes the text
 *
 * The section of the version is the text. An HTML comment right below its heading names the title,
 * which the changelog does not show:
 *
 *   ## [0.0.10] - 2026-11-02
 *   <!-- title: Forge connections and early warnings -->
 *
 * Links relative to the repository (docs/..., CHANGELOG.md) point to the files at the tag.
 */
import { readFileSync, writeFileSync } from "node:fs";

const REPOSITORY = "https://github.com/lcsfls/garnet-ops";

/**
 * Joins lines the changelog wraps at its line length: GitHub shows every line break of a release text,
 * so a wrapped list item would read as several broken lines. Code blocks stay as they are.
 */
function unwrap(lines) {
  const out = [];
  let fenced = false;
  for (const line of lines) {
    if (/^\s*```/.test(line)) fenced = !fenced;
    const previous = out.at(-1);
    const continues =
      !fenced &&
      previous !== undefined &&
      previous.trim() !== "" &&
      !/^\s*(#|```)/.test(previous) &&
      /^\s+\S/.test(line) &&
      !/^\s*([-*+]|\d+\.)\s/.test(line) &&
      !/^ {4,}/.test(line.replace(/^ {2}/, ""));
    if (continues) out[out.length - 1] = `${previous} ${line.trim()}`;
    else out.push(line);
  }
  return out;
}

/** The section of `version` (without its heading) and the title from its comment, or null. */
export function releaseNotes(changelog, tag) {
  const version = tag.replace(/^v/, "");
  const lines = changelog.split("\n");
  const start = lines.findIndex((line) => line.startsWith(`## [${version}]`));
  if (start === -1) return null;
  let end = lines.findIndex((line, i) => i > start && /^## |^\[[^\]]+\]: /.test(line));
  if (end === -1) end = lines.length;
  let title = null;
  const body = [];
  for (const line of lines.slice(start + 1, end)) {
    const comment = /^<!--\s*title:\s*(.+?)\s*-->$/.exec(line.trim());
    if (comment) title = comment[1];
    else body.push(line);
  }
  const blob = `${REPOSITORY}/blob/${tag}/`;
  const text = unwrap(body)
    .join("\n")
    .trim()
    // [label](docs/x.md) -> the file at the tag; absolute links and anchors stay as they are.
    .replace(/\]\((?![a-z]+:|#)([^)]+)\)/g, (_, path) => `](${blob}${path.replace(/^\.?\//, "")})`);
  return {
    title: title ? `${tag} – ${title}` : tag,
    text: `${text}\n\nFull list of changes: [CHANGELOG.md](${blob}CHANGELOG.md)\n`,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [tag, out] = process.argv.slice(2);
  if (!tag || !out) {
    console.error("usage: node scripts/release-notes.mjs <tag> <notes file>");
    process.exit(2);
  }
  const notes = releaseNotes(readFileSync("CHANGELOG.md", "utf8"), tag);
  if (!notes) {
    console.error(`CHANGELOG.md has no section for ${tag}`);
    process.exit(1);
  }
  writeFileSync(out, notes.text);
  console.log(notes.title);
}
