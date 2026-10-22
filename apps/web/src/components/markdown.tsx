import { Check, Copy } from "lucide-react";
import { type ReactNode, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { type Block, type Inline, type List, parseMarkdown } from "../lib/markdown.ts";

/**
 * The tree has no ids. Its order is stable (an answer only grows at its tail while it streams),
 * so a running number is a correct key.
 */
function keyed<T>(items: T[]): [number, T][] {
  let next = 0;
  return items.map((item) => [next++, item]);
}

/**
 * Renders the model's Markdown (ADR 0013) as React elements built from the parser's tree.
 * There is no HTML anywhere on this path: text is escaped by React, links exist only for
 * http(s) addresses and always name their host, and nothing carries a style or a script.
 */
export function Markdown({ text }: { text: string }) {
  const { t } = useTranslation();
  const { blocks, truncated } = useMemo(() => parseMarkdown(text), [text]);
  return (
    <div className="grid min-w-0 gap-2.5 leading-relaxed break-words">
      {keyed(blocks).map(([key, block]) => (
        <BlockView key={key} block={block} />
      ))}
      {truncated ? <p className="text-sm text-muted-foreground">{t("ai.truncatedMarkdown")}</p> : null}
    </div>
  );
}

function BlockView({ block }: { block: Block }) {
  switch (block.t) {
    case "p":
      return <p className="whitespace-pre-line">{renderInline(block.c)}</p>;
    case "heading":
      return <p className="font-semibold">{renderInline(block.c)}</p>;
    case "quote":
      return (
        <blockquote className="border-l-2 pl-3 whitespace-pre-line text-muted-foreground">
          {renderInline(block.c)}
        </blockquote>
      );
    case "code":
      return <CodeBlock code={block.v} language={block.lang} />;
    case "list":
      return <ListView list={block} />;
  }
}

function ListView({ list }: { list: List }) {
  const Tag = list.ordered ? "ol" : "ul";
  return (
    <Tag className={list.ordered ? "ml-5 list-decimal space-y-1" : "ml-5 list-disc space-y-1"}>
      {keyed(list.items).map(([key, item]) => (
        <li key={key} className="pl-0.5">
          {renderInline(item.c)}
          {item.sub ? <ListView list={item.sub} /> : null}
        </li>
      ))}
    </Tag>
  );
}

/** A code block with its own copy button; long lines scroll inside the block. */
function CodeBlock({ code, language }: { code: string; language: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  return (
    <div className="overflow-hidden rounded-lg border bg-muted">
      <div className="flex items-center gap-2 border-b px-3 py-1 text-[13px] text-muted-foreground">
        <span className="font-mono">{language || "text"}</span>
        <button
          type="button"
          className="ml-auto inline-flex h-7 items-center gap-1.5 rounded-md px-2 hover:bg-accent"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(code);
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
            } catch {
              // The clipboard can be blocked; the text stays selectable.
            }
          }}
        >
          {copied ? (
            <Check aria-hidden="true" className="size-3.5" />
          ) : (
            <Copy aria-hidden="true" className="size-3.5" />
          )}
          {copied ? t("ai.copied") : t("ai.copy")}
        </button>
      </div>
      <pre className="overflow-x-auto p-3 font-mono text-[13px] leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function renderInline(nodes: Inline[]): ReactNode[] {
  return keyed(nodes).map(([key, node]) => <InlineView key={key} node={node} />);
}

function InlineView({ node }: { node: Inline }): ReactNode {
  if (node.t === "text") return node.v;
  if (node.t === "code") {
    return <code className="rounded bg-muted px-1 py-px font-mono text-[0.9em] break-all">{node.v}</code>;
  }
  if (node.t === "strong") return <strong>{renderInline(node.c)}</strong>;
  if (node.t === "em") return <em>{renderInline(node.c)}</em>;
  return (
    <span>
      <a
        href={node.href}
        target="_blank"
        rel="noopener noreferrer nofollow"
        className="text-primary-text underline-offset-4 hover:underline"
      >
        {renderInline(node.c)}
      </a>
      <span className="text-[0.9em] text-muted-foreground"> ({node.host})</span>
    </span>
  );
}
