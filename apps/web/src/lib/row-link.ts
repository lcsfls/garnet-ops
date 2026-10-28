/**
 * Click handler for a table row that opens something (mockup: whole rows are clickable).
 * The row's own link stays the keyboard and screen-reader path; this only adds the
 * larger mouse target. Clicks on controls inside the row, modified clicks (new tab via
 * the link) and text selection are left alone.
 */
export function rowClick(open: () => void) {
  return (event: MouseEvent) => {
    if (event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const target = event.target as HTMLElement;
    if (target.closest("a, button, input, select, textarea, label, summary, dialog, [role='menu']")) return;
    if (window.getSelection()?.toString()) return;
    open();
  };
}
