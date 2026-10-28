<script lang="ts">
  import { t } from "../i18n.svelte.ts";
  import { type Inline, type List, parseMarkdown } from "../markdown.ts";
  import MarkdownCodeBlock from "./MarkdownCodeBlock.svelte";

  /**
   * Renders the model's Markdown (ADR 0013) as Svelte elements built from the parser's tree. There is no HTML anywhere
   * on this path (never {@html}): text is escaped by Svelte, links exist only for http(s) addresses and always name
   * their host, and nothing carries a style or a script.
   *
   * The tree has no ids. Its order is stable (an answer only grows at its tail while it streams), so the position is a
   * correct key: the lists below are unkeyed, which Svelte updates by index.
   */
  let { text }: { text: string } = $props();
  const parsed = $derived(parseMarkdown(text));
</script>

<!--
  The inline snippet is written without whitespace between its tags on purpose: the paragraphs keep line breaks
  (whitespace-pre-line), so any whitespace of the template would show up in the text.
-->
{#snippet inline(nodes: Inline[])}{#each nodes as node}{#if node.t === "text"}{node.v}{:else if node.t === "code"}<code
        class="rounded bg-muted px-1 py-px font-mono text-[0.9em] break-all">{node.v}</code
      >{:else if node.t === "strong"}<strong>{@render inline(node.c)}</strong>{:else if node.t === "em"}<em
        >{@render inline(node.c)}</em
      >{:else}<span
        ><a
          href={node.href}
          target="_blank"
          rel="noopener noreferrer nofollow"
          class="text-primary-text underline-offset-4 hover:underline">{@render inline(node.c)}</a
        ><span class="text-[0.9em] text-muted-foreground">{` (${node.host})`}</span></span
      >{/if}{/each}{/snippet}

{#snippet listView(list: List)}
  <svelte:element this={list.ordered ? "ol" : "ul"} class={list.ordered ? "ml-5 list-decimal space-y-1" : "ml-5 list-disc space-y-1"}>
    {#each list.items as item}
      <li class="pl-0.5">{@render inline(item.c)}{#if item.sub}{@render listView(item.sub)}{/if}</li>
    {/each}
  </svelte:element>
{/snippet}

<div class="grid min-w-0 gap-2.5 leading-relaxed break-words">
  {#each parsed.blocks as block}
    {#if block.t === "p"}
      <p class="whitespace-pre-line">{@render inline(block.c)}</p>
    {:else if block.t === "heading"}
      <p class="font-semibold">{@render inline(block.c)}</p>
    {:else if block.t === "quote"}
      <blockquote class="border-l-2 pl-3 whitespace-pre-line text-muted-foreground">{@render inline(block.c)}</blockquote>
    {:else if block.t === "code"}
      <MarkdownCodeBlock code={block.v} language={block.lang} />
    {:else}
      {@render listView(block)}
    {/if}
  {/each}
  {#if parsed.truncated}<p class="text-sm text-muted-foreground">{t("ai.truncatedMarkdown")}</p>{/if}
</div>
