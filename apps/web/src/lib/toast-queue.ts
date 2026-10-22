/**
 * The logic of the toast messages (ADR 0019), kept apart from React so it can be tested: at most
 * three are shown, errors stay until they are closed, a repeat of a message that is already shown
 * does not stack, and what does not fit waits its turn.
 */

export type ToastKind = "success" | "error" | "info";

export interface ToastInput {
  kind: ToastKind;
  message: string;
  /** A link inside the app offered with the message ("View"). */
  action?: { label: string; href: string };
  /** Milliseconds until it closes by itself; null stays until closed. Errors always stay. */
  durationMs?: number | null;
}

export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
  action: { label: string; href: string } | null;
  /** null: stays until closed. */
  durationMs: number | null;
  /** Grows when the same message is shown again, so its timer starts over. */
  revision: number;
}

export interface ToastState {
  visible: Toast[];
  waiting: Toast[];
  nextId: number;
}

export const MAX_VISIBLE_TOASTS = 3;
/** Beyond this many waiting messages the oldest waiting one is dropped. */
export const MAX_WAITING_TOASTS = 20;
export const DEFAULT_DURATION_MS = 6_000;
/** A message with an action to take gets a little longer. */
export const ACTION_DURATION_MS = 10_000;

export const initialToasts: ToastState = { visible: [], waiting: [], nextId: 1 };

export type ToastAction =
  | { type: "add"; toast: ToastInput }
  | { type: "dismiss"; id: number }
  | { type: "clear" };

function durationOf(input: ToastInput): number | null {
  if (input.kind === "error") return null;
  if (input.durationMs !== undefined) return input.durationMs;
  return input.action ? ACTION_DURATION_MS : DEFAULT_DURATION_MS;
}

const same = (a: Toast, input: ToastInput) => a.kind === input.kind && a.message === input.message;

/** Fills free places from the waiting list, oldest first. */
function promote(state: ToastState): ToastState {
  if (state.waiting.length === 0 || state.visible.length >= MAX_VISIBLE_TOASTS) return state;
  const room = MAX_VISIBLE_TOASTS - state.visible.length;
  return {
    ...state,
    visible: [...state.visible, ...state.waiting.slice(0, room)],
    waiting: state.waiting.slice(room),
  };
}

export function toastReducer(state: ToastState, action: ToastAction): ToastState {
  switch (action.type) {
    case "add": {
      const input = action.toast;
      // The same message again: keep one, and let its timer start over.
      const repeat = state.visible.find((t) => same(t, input));
      if (repeat) {
        return {
          ...state,
          visible: state.visible.map((t) => (t === repeat ? { ...t, revision: t.revision + 1 } : t)),
        };
      }
      if (state.waiting.some((t) => same(t, input))) return state;
      const toast: Toast = {
        id: state.nextId,
        kind: input.kind,
        message: input.message,
        action: input.action ?? null,
        durationMs: durationOf(input),
        revision: 0,
      };
      const next = { ...state, nextId: state.nextId + 1 };
      if (next.visible.length < MAX_VISIBLE_TOASTS) return { ...next, visible: [...next.visible, toast] };
      // Full: make room by letting the oldest message that closes by itself go. Errors are never
      // pushed out; with three errors showing, the new message waits.
      const evict = next.visible.find((t) => t.durationMs !== null);
      if (evict) {
        return { ...next, visible: [...next.visible.filter((t) => t !== evict), toast] };
      }
      return { ...next, waiting: [...next.waiting, toast].slice(-MAX_WAITING_TOASTS) };
    }
    case "dismiss": {
      const visible = state.visible.filter((t) => t.id !== action.id);
      const waiting = state.waiting.filter((t) => t.id !== action.id);
      if (visible.length === state.visible.length && waiting.length === state.waiting.length) return state;
      return promote({ ...state, visible, waiting });
    }
    case "clear":
      return { ...state, visible: [], waiting: [] };
  }
}
