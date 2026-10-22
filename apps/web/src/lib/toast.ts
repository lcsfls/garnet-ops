import { useSyncExternalStore } from "react";
import { initialToasts, type ToastInput, type ToastState, toastReducer } from "./toast-queue.ts";

/**
 * The toast store (ADR 0019): a module-level state so any code, React or not, can show a message
 * (`toast.success(t("...saved"))`). The region that draws them is `ToastRegion`. Messages are
 * already translated by the caller and are always rendered as text.
 */
let state: ToastState = initialToasts;
const listeners = new Set<() => void>();

function dispatch(action: Parameters<typeof toastReducer>[1]): void {
  const next = toastReducer(state, action);
  if (next === state) return;
  state = next;
  for (const listener of listeners) listener();
}

type Options = Pick<ToastInput, "action" | "durationMs">;

export const toast = {
  success: (message: string, options: Options = {}) =>
    dispatch({ type: "add", toast: { kind: "success", message, ...options } }),
  error: (message: string, options: Options = {}) =>
    dispatch({ type: "add", toast: { kind: "error", message, ...options } }),
  info: (message: string, options: Options = {}) =>
    dispatch({ type: "add", toast: { kind: "info", message, ...options } }),
  dismiss: (id: number) => dispatch({ type: "dismiss", id }),
  clear: () => dispatch({ type: "clear" }),
};

export function useToasts(): ToastState {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => state,
    () => state,
  );
}
