/**
 * Syntax highlighting for the code viewer (ADR 0048). highlight.js escapes the text and wraps tokens in `<span class="hljs-…">`;
 * its output is never put into the page as HTML. It is read back by a strict parser that knows only those spans, their closing
 * tags and the five escapes highlight.js writes, and becomes plain tokens that Svelte renders as text. Anything else stays text.
 * The language is chosen by file name (never guessed from content), from a fixed set bundled here.
 */
import hljs from "highlight.js/lib/core";
import bash from "highlight.js/lib/languages/bash";
import dockerfile from "highlight.js/lib/languages/dockerfile";
import go from "highlight.js/lib/languages/go";
import ini from "highlight.js/lib/languages/ini";
import javascript from "highlight.js/lib/languages/javascript";
import json from "highlight.js/lib/languages/json";
import php from "highlight.js/lib/languages/php";
import python from "highlight.js/lib/languages/python";
import rust from "highlight.js/lib/languages/rust";
import typescript from "highlight.js/lib/languages/typescript";
import xml from "highlight.js/lib/languages/xml";
import yaml from "highlight.js/lib/languages/yaml";

const LANGUAGES = { bash, dockerfile, go, ini, javascript, json, php, python, rust, typescript, xml, yaml };
for (const [name, language] of Object.entries(LANGUAGES)) hljs.registerLanguage(name, language);

/** A piece of a line: its text, and the highlight.js classes it carries (only `hljs-…` ones). */
export interface CodeToken {
  text: string;
  classes: string;
}

const ENTITIES: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#x27;": "'",
};
const decode = (text: string) => text.replace(/&(?:amp|lt|gt|quot|#x27);/g, (e) => ENTITIES[e] ?? e);

/** highlight.js' HTML as tokens; exported for its tests. */
export function tokensOfHtml(html: string): CodeToken[] {
  const out: CodeToken[] = [];
  const stack: string[] = [];
  const re = /<span class="([a-z0-9_ -]{1,80})">|<\/span>|([^<]+)|(<)/g;
  for (const m of html.matchAll(re)) {
    if (m[1] !== undefined) {
      const kept = m[1].split(" ").filter((c) => /^hljs-[a-z_]{1,40}$/.test(c));
      stack.push(kept.join(" "));
    } else if (m[0] === "</span>") {
      stack.pop();
    } else {
      // Text, or a stray "<" highlight.js would never write: either way, plain text.
      const text = m[2] !== undefined ? decode(m[2]) : "<";
      const classes = stack.filter(Boolean).at(-1) ?? "";
      const last = out.at(-1);
      if (last && last.classes === classes) last.text += text;
      else out.push({ text, classes });
    }
  }
  return out;
}

/** One line as tokens; a language highlight.js does not know here, or none, gives the plain line. */
export function highlightLine(text: string, language: string | null): CodeToken[] {
  if (!language || !hljs.getLanguage(language) || text === "") return [{ text, classes: "" }];
  try {
    return tokensOfHtml(hljs.highlight(text, { language, ignoreIllegals: true }).value);
  } catch {
    return [{ text, classes: "" }];
  }
}
