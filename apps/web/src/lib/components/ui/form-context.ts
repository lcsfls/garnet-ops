import { createContext } from "svelte";

/** Whether a field sits in a FormRow, where it shares label, control and note rows with its neighbours. */
export const [inFormRow, setInFormRow, hasFormRow] = createContext<boolean>();

/** What a control needs to be wired to its label, hint and error. */
export interface ControlProps {
  id: string;
  "aria-describedby": string | undefined;
  "aria-invalid": true | undefined;
}
