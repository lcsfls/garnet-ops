/** Most repositories one request may add (the API's limit). */
export const BULK_LIMIT = 50;

/** The repository addresses of a pasted list: one per line, blank lines ignored, each once. */
export function parseUrlList(text: string): string[] {
  return [
    ...new Set(
      text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean),
    ),
  ];
}
