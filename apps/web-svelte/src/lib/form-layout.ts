/**
 * Columns of a form row with fields side by side (see `FormRow` in components/ui/field.tsx).
 * A number gives that many equal columns; a list gives each column's track size, e.g.
 * `["minmax(0,1fr)", "8rem"]` for a wide field and a narrow one. Every track may shrink to
 * zero, so a long value never pushes the row past its card (AGENTS.md rule 5).
 */
export type FormColumns = number | readonly string[];

/** Container-query steps from which the fields sit side by side; below it they stack. */
export const FORM_ROW_STEPS = ["sm", "md", "lg", "xl"] as const;
export type FormRowStep = (typeof FORM_ROW_STEPS)[number];

const TRACK = /^(minmax\(0,\s*[\d.]+fr\)|[\d.]+(rem|px|%|ch)|[\d.]+fr|auto)$/;

/** The `grid-template-columns` value for `columns`; throws on a track that could overflow its card. */
export function formColumnTemplate(columns: FormColumns): string {
  if (typeof columns === "number") {
    if (!Number.isInteger(columns) || columns < 1 || columns > 4) {
      throw new RangeError(`A form row has 1 to 4 columns, not ${columns}`);
    }
    return Array.from({ length: columns }, () => "minmax(0,1fr)").join(" ");
  }
  if (columns.length < 1 || columns.length > 4) {
    throw new RangeError(`A form row has 1 to 4 columns, not ${columns.length}`);
  }
  return columns
    .map((track) => {
      const trimmed = track.trim();
      if (!TRACK.test(trimmed)) throw new RangeError(`Not a column size: ${track}`);
      // A bare fraction would not shrink below its content; make it shrinkable.
      return /^[\d.]+fr$/.test(trimmed) ? `minmax(0,${trimmed})` : trimmed;
    })
    .join(" ");
}
