/**
 * A small Markdown parser for the model's answers (ADR 0013). The answer is untrusted, so this
 * is deliberately less than Markdown: it produces a tree of a few node types and never HTML.
 * The renderer (components/markdown.tsx) turns the tree into React elements, which escape all
 * text. There is no way to write a raw tag, an attribute, an image or a script.
 *
 * Supported: paragraphs, headings, bullet and numbered lists (two levels), block quotes,
 * fenced code, inline code, **bold**, *italic* / _italic_, and links. A link is kept only for
 * http(s) addresses without credentials; anything else is shown as plain text, together with
 * its address, so nothing is hidden from the reader.
 *
 * Linear in the size of the input: every delimiter that is not closed is remembered as
 * unclosed, so a long run of "**" cannot make the parser quadratic. The input, the number of
 * blocks and the nesting are capped.
 */

export type Inline =
  | { t: "text"; v: string }
  | { t: "code"; v: string }
  | { t: "strong"; c: Inline[] }
  | { t: "em"; c: Inline[] }
  | { t: "link"; href: string; host: string; c: Inline[] };

export interface ListItem {
  c: Inline[];
  /** One nested list. */
  sub?: List;
}
export interface List {
  t: "list";
  ordered: boolean;
  items: ListItem[];
}
export type Block =
  | { t: "p"; c: Inline[] }
  | { t: "heading"; level: 1 | 2 | 3; c: Inline[] }
  | { t: "code"; lang: string; v: string }
  | { t: "quote"; c: Inline[] }
  | List;

export const MARKDOWN_LIMITS = { chars: 60_000, blocks: 500, depth: 4, listItems: 200 } as const;

const PUNCTUATION = "\\`*_{}[]()#+-.!|<>~&\"'";

/** The address of a link if it may become one: http(s), a host, no credentials. */
export function safeLink(value: string): { href: string; host: string } | null {
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  if (url.username || url.password || !url.host) return null;
  return { href: url.href, host: url.host };
}

const isSpace = (c: string | undefined) => c === undefined || /\s/.test(c);
const isWord = (c: string | undefined) => c !== undefined && /[\p{L}\p{N}]/u.test(c);

/** The index of the closing delimiter for an opener at `from - delimiter.length`, or -1. */
function findClose(s: string, delimiter: string, from: number): number {
  let at = s.indexOf(delimiter, from);
  while (at >= 0) {
    const before = s[at - 1];
    const after = s[at + delimiter.length];
    if (at > from && !isSpace(before)) {
      if (delimiter.length === 2) return at;
      // A single * or _ must not be part of a longer run, and _ must end a word.
      const run = before !== delimiter && after !== delimiter;
      if (run && (delimiter === "*" || !isWord(after))) return at;
    }
    at = s.indexOf(delimiter, at + 1);
  }
  return -1;
}

export function parseInline(source: string, depth = 0, inLink = false): Inline[] {
  const out: Inline[] = [];
  let buffer = "";
  const flush = () => {
    if (buffer) out.push({ t: "text", v: buffer });
    buffer = "";
  };
  // Delimiters known to have no closing partner further on: no point in searching again.
  const unclosed = new Set<string>();
  let i = 0;
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === "\\" && i + 1 < source.length && PUNCTUATION.includes(source[i + 1] as string)) {
      buffer += source[i + 1];
      i += 2;
      continue;
    }
    if (ch === "`") {
      let run = 1;
      while (source[i + run] === "`") run++;
      const fence = "`".repeat(run);
      const key = `code${run}`;
      const close = unclosed.has(key) ? -1 : source.indexOf(fence, i + run);
      if (close > i + run - 1 && source[close + run] !== "`") {
        flush();
        out.push({ t: "code", v: source.slice(i + run, close).replace(/^ (.*) $/s, "$1") });
        i = close + run;
        continue;
      }
      if (close < 0) unclosed.add(key);
      buffer += fence;
      i += run;
      continue;
    }
    if (depth < MARKDOWN_LIMITS.depth && (ch === "*" || ch === "_")) {
      const double = source[i + 1] === ch;
      const delimiter = double ? ch + ch : ch;
      const start = i + delimiter.length;
      const opens = !isSpace(source[start]) && (ch === "*" || !isWord(source[i - 1]));
      if (opens && !unclosed.has(delimiter)) {
        const close = findClose(source, delimiter, start);
        if (close > start) {
          flush();
          const c = parseInline(source.slice(start, close), depth + 1, inLink);
          out.push({ t: double ? "strong" : "em", c });
          i = close + delimiter.length;
          continue;
        }
        unclosed.add(delimiter);
      }
      buffer += delimiter;
      i += delimiter.length;
      continue;
    }
    if ((ch === "[" || (ch === "!" && source[i + 1] === "[")) && depth < MARKDOWN_LIMITS.depth) {
      const image = ch === "!";
      const open = image ? i + 1 : i;
      const closeText = unclosed.has("[") ? -1 : source.indexOf("]", open + 1);
      if (closeText < 0) unclosed.add("[");
      if (closeText > open && source[closeText + 1] === "(") {
        const closeUrl = source.indexOf(")", closeText + 2);
        if (closeUrl > closeText) {
          const label = source.slice(open + 1, closeText);
          // The address, without an optional title after a space.
          const target =
            source
              .slice(closeText + 2, closeUrl)
              .trim()
              .split(/\s+/)[0] ?? "";
          const link = image || inLink ? null : safeLink(target);
          flush();
          if (link)
            out.push({ t: "link", href: link.href, host: link.host, c: parseInline(label, depth + 1, true) });
          else {
            // Not a link we show: the text and, so nothing is hidden, the address as plain text.
            out.push(...parseInline(label, depth + 1, true));
            if (target) out.push({ t: "text", v: ` (${target})` });
          }
          i = closeUrl + 1;
          continue;
        }
      }
    }
    buffer += ch;
    i++;
  }
  flush();
  return out;
}

const FENCE = /^ {0,3}(`{3,}|~{3,})\s*([\w+#.-]{0,30})\s*$/;
const HEADING = /^ {0,3}(#{1,6})\s+(.*)$/;
const ITEM = /^( *)([-*+]|\d{1,9}[.)])\s+(.*)$/;
const QUOTE = /^ {0,3}>\s?(.*)$/;
const MAX_STRUCTURE_LINE = 4_000;
const RULE = /^ {0,3}([-*_])( *\1){2,} *$/;

/** Parses Markdown into blocks. Returns the blocks and whether the input was cut. */
export function parseMarkdown(input: string): { blocks: Block[]; truncated: boolean } {
  const truncated = input.length > MARKDOWN_LIMITS.chars;
  const lines = (truncated ? input.slice(0, MARKDOWN_LIMITS.chars) : input).split(/\r\n|\r|\n/);
  const blocks: Block[] = [];
  let paragraph: string[] = [];
  let list: List | null = null;
  let listItems = 0;
  const closeParagraph = () => {
    if (paragraph.length) blocks.push({ t: "p", c: parseInline(paragraph.join("\n")) });
    paragraph = [];
  };
  const closeList = () => {
    list = null;
  };
  const full = () => blocks.length >= MARKDOWN_LIMITS.blocks;

  for (let n = 0; n < lines.length && !full(); n++) {
    const line = lines[n] as string;
    // A very long line is text, not structure: the patterns below are for ordinary lines.
    if (line.length > MAX_STRUCTURE_LINE) {
      closeList();
      paragraph.push(line);
      continue;
    }
    const fence = FENCE.exec(line);
    if (fence) {
      closeParagraph();
      closeList();
      const marker = (fence[1] as string)[0] as string;
      const size = (fence[1] as string).length;
      const body: string[] = [];
      const closing = new RegExp(`^ {0,3}\\${marker}{${size},}\\s*$`);
      n++;
      // An unclosed fence runs to the end: the answer may still be arriving.
      while (n < lines.length) {
        if (closing.test(lines[n] as string)) break;
        body.push(lines[n] as string);
        n++;
      }
      blocks.push({ t: "code", lang: (fence[2] as string) || "", v: body.join("\n") });
      continue;
    }
    if (line.trim() === "") {
      closeParagraph();
      // A blank line between two items of the same list does not end it.
      continue;
    }
    const heading = HEADING.exec(line);
    if (heading) {
      closeParagraph();
      closeList();
      const level = Math.min(3, (heading[1] as string).length) as 1 | 2 | 3;
      blocks.push({ t: "heading", level, c: parseInline((heading[2] as string).replace(/[\s#]+$/, "")) });
      continue;
    }
    if (RULE.test(line)) {
      closeParagraph();
      closeList();
      continue;
    }
    const item = ITEM.exec(line);
    if (item && listItems < MARKDOWN_LIMITS.listItems) {
      closeParagraph();
      listItems++;
      const indent = (item[1] as string).length;
      const ordered = /\d/.test(item[2] as string);
      const entry: ListItem = { c: parseInline(item[3] as string) };
      const current = list as List | null;
      if (indent >= 2 && current && current.items.length > 0) {
        const parent = current.items[current.items.length - 1] as ListItem;
        parent.sub ??= { t: "list", ordered, items: [] };
        parent.sub.items.push(entry);
      } else if (current && current.ordered === ordered) {
        current.items.push(entry);
      } else {
        list = { t: "list", ordered, items: [entry] };
        blocks.push(list);
      }
      continue;
    }
    const quote = QUOTE.exec(line);
    if (quote) {
      closeParagraph();
      closeList();
      const last = blocks[blocks.length - 1];
      if (last?.t === "quote") last.c.push({ t: "text", v: "\n" }, ...parseInline(quote[1] as string));
      else blocks.push({ t: "quote", c: parseInline(quote[1] as string) });
      continue;
    }
    // A continuation line of a list item (indented text) belongs to that item.
    const current = list as List | null;
    if (current && /^\s{2,}\S/.test(line) && paragraph.length === 0) {
      const target = current.items[current.items.length - 1] as ListItem;
      const holder = target.sub?.items[target.sub.items.length - 1] ?? target;
      holder.c.push({ t: "text", v: " " }, ...parseInline(line.trim()));
      continue;
    }
    closeList();
    paragraph.push(line);
  }
  closeParagraph();
  return { blocks, truncated: truncated || full() };
}
