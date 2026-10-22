import {
  type CSSProperties,
  createContext,
  type InputHTMLAttributes,
  type ReactNode,
  type TextareaHTMLAttributes,
  useContext,
  useId,
} from "react";
import { cn } from "../../lib/cn.ts";
import {
  FORM_ROW_STEPS,
  type FormColumns,
  type FormRowStep,
  formColumnTemplate,
} from "../../lib/form-layout.ts";

/** Whether a field sits in a {@link FormRow}, where it shares label, control and note rows with its neighbours. */
const FormRowContext = createContext(false);

/**
 * Container-query steps are written out in full so Tailwind finds them. They refer to the
 * row's own box (the card or dialog it sits in), not to the page.
 */
const SIDE_BY_SIDE: Record<FormRowStep, string> = {
  sm: "@sm:grid-cols-(--form-columns)",
  md: "@md:grid-cols-(--form-columns)",
  lg: "@lg:grid-cols-(--form-columns)",
  xl: "@xl:grid-cols-(--form-columns)",
};

/**
 * Fields side by side. Every field spans three rows of this grid (label, control, note), so
 * the labels sit on one line, the controls on the next and the hints below, however long a
 * label or hint is. Below `from` the fields stack. Use it for every form row with more than
 * one field; a single field needs no row.
 *
 * Each field's box is a subgrid of the row, which is why a plain `grid` per field (whose rows
 * stretch to the tallest neighbour) is not enough: it pushed the shorter field's control down.
 */
export function FormRow({
  columns = 2,
  from = "md",
  children,
}: {
  columns?: FormColumns;
  from?: FormRowStep;
  children: ReactNode;
}) {
  if (!FORM_ROW_STEPS.includes(from)) throw new RangeError(`Not a form row step: ${from}`);
  const style = { "--form-columns": formColumnTemplate(columns) } as CSSProperties;
  return (
    <FormRowContext.Provider value={true}>
      {/* Each note row ends with the gap that separates bands of fields; the last one is taken back here. */}
      <div className="@container -mb-4">
        <div data-form-row style={style} className={cn("grid grid-cols-1 gap-x-4", SIDE_BY_SIDE[from])}>
          {children}
        </div>
      </div>
    </FormRowContext.Provider>
  );
}

/** What a control needs to be wired to its label, hint and error. */
export interface ControlProps {
  id: string;
  "aria-describedby": string | undefined;
  "aria-invalid": true | undefined;
}

interface ShellProps {
  label: string;
  hint?: string | undefined;
  error?: string | null | undefined;
  id: string;
  children: (control: ControlProps) => ReactNode;
}

/** Label, control, hint and error. In a {@link FormRow} the three parts take the row's shared rows. */
function Shell({ label, hint, error, id, children }: ShellProps) {
  const inRow = useContext(FormRowContext);
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const control = children({
    id,
    "aria-describedby": [hintId, errorId].filter(Boolean).join(" ") || undefined,
    "aria-invalid": error ? true : undefined,
  });
  const hintText = hint ? (
    <p id={hintId} className={cn("text-sm text-muted-foreground", inRow && "pt-1.5")}>
      {hint}
    </p>
  ) : null;
  const errorText = error ? (
    <p id={errorId} className={cn("text-sm text-destructive-text", inRow && "pt-1.5")}>
      {error}
    </p>
  ) : null;
  if (!inRow) {
    return (
      <div className="grid gap-1.5">
        <label htmlFor={id} className="text-sm font-medium">
          {label}
        </label>
        <div className="grid" data-field-control>
          {control}
        </div>
        {hintText}
        {errorText}
      </div>
    );
  }
  return (
    <div className="row-span-3 grid grid-rows-subgrid">
      <label htmlFor={id} data-field-label className="pb-1.5 text-sm font-medium">
        {label}
      </label>
      <div className="grid content-start" data-field-control>
        {control}
      </div>
      <div className="pb-4" data-field-note>
        {hintText}
        {errorText}
      </div>
    </div>
  );
}

const INPUT =
  "h-10 w-full rounded-md border border-input bg-card px-3 text-base shadow-xs " +
  "placeholder:text-muted-foreground aria-invalid:border-destructive disabled:opacity-50";

export interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: string;
  error?: string | null;
}

/** Label, input, hint and error wired together for screen readers. */
export function Field({ label, hint, error, className, id, ...props }: FieldProps) {
  const generated = useId();
  return (
    <Shell label={label} hint={hint} error={error} id={id ?? generated}>
      {(control) => <input {...control} className={cn(INPUT, className)} {...props} />}
    </Shell>
  );
}

export interface TextAreaFieldProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label: string;
  hint?: string;
  error?: string | null;
}

/** Field for several lines, wired like {@link Field}. */
export function TextAreaField({ label, hint, error, className, id, ...props }: TextAreaFieldProps) {
  const generated = useId();
  return (
    <Shell label={label} hint={hint} error={error} id={id ?? generated}>
      {(control) => (
        <textarea
          {...control}
          className={cn(
            "min-h-24 w-full rounded-md border border-input bg-card px-3 py-2 text-base shadow-xs",
            "placeholder:text-muted-foreground aria-invalid:border-destructive",
            className,
          )}
          {...props}
        />
      )}
    </Shell>
  );
}

/**
 * Label, hint and error around a control that is not a plain input (a select, a time picker
 * with a button). The control gets its id and descriptions from the render function:
 * `<FormField label="Zone">{(control) => <Select {...control} />}</FormField>`.
 */
export function FormField({
  label,
  hint,
  error,
  id,
  children,
}: {
  label: string;
  hint?: string;
  error?: string | null;
  id?: string;
  children: (control: ControlProps) => ReactNode;
}) {
  const generated = useId();
  return (
    <Shell label={label} hint={hint} error={error} id={id ?? generated}>
      {children}
    </Shell>
  );
}
