import { describe, expect, it } from "vitest";
import {
  ACTION_DURATION_MS,
  DEFAULT_DURATION_MS,
  initialToasts,
  MAX_VISIBLE_TOASTS,
  MAX_WAITING_TOASTS,
  type ToastAction,
  type ToastInput,
  type ToastState,
  toastReducer,
} from "./toast-queue.ts";

const run = (actions: ToastAction[], from: ToastState = initialToasts) => actions.reduce(toastReducer, from);
const add = (toast: ToastInput): ToastAction => ({ type: "add", toast });
const ok = (message: string): ToastAction => add({ kind: "success", message });
const bad = (message: string): ToastAction => add({ kind: "error", message });
const messages = (state: ToastState) => state.visible.map((t) => t.message);

describe("toast queue", () => {
  it("shows messages in the order they come, with their own ids", () => {
    const state = run([ok("one"), ok("two")]);
    expect(messages(state)).toEqual(["one", "two"]);
    expect(state.visible.map((t) => t.id)).toEqual([1, 2]);
  });

  it("closes success and information by themselves, and keeps errors until they are closed", () => {
    const state = run([ok("saved"), bad("failed"), add({ kind: "info", message: "fyi" })]);
    expect(state.visible.map((t) => t.durationMs)).toEqual([DEFAULT_DURATION_MS, null, DEFAULT_DURATION_MS]);
    // An error cannot be given a time to leave.
    const forced = run([add({ kind: "error", message: "x", durationMs: 1000 })]);
    expect(forced.visible[0]?.durationMs).toBeNull();
    const longer = run([add({ kind: "info", message: "x", action: { label: "View", href: "/a" } })]);
    expect(longer.visible[0]?.durationMs).toBe(ACTION_DURATION_MS);
    expect(run([add({ kind: "info", message: "x", durationMs: 1234 })]).visible[0]?.durationMs).toBe(1234);
  });

  it("shows at most three; a fourth pushes out the oldest one that closes by itself", () => {
    const state = run([ok("a"), bad("b"), ok("c"), ok("d")]);
    expect(state.visible).toHaveLength(MAX_VISIBLE_TOASTS);
    expect(messages(state)).toEqual(["b", "c", "d"]);
    expect(state.waiting).toEqual([]);
  });

  it("never pushes an error out: a message that finds three errors waits, and appears when one is closed", () => {
    const full = run([bad("e1"), bad("e2"), bad("e3"), ok("later")]);
    expect(messages(full)).toEqual(["e1", "e2", "e3"]);
    expect(full.waiting.map((t) => t.message)).toEqual(["later"]);
    const after = toastReducer(full, { type: "dismiss", id: full.visible[0]?.id ?? 0 });
    expect(messages(after)).toEqual(["e2", "e3", "later"]);
    expect(after.waiting).toEqual([]);
  });

  it("does not stack a message that is already shown: it starts its timer over", () => {
    const state = run([ok("saved"), ok("other"), ok("saved")]);
    expect(messages(state)).toEqual(["saved", "other"]);
    expect(state.visible[0]?.revision).toBe(1);
    expect(state.visible[1]?.revision).toBe(0);
    // The same text as an error is a different message.
    expect(messages(run([ok("x"), bad("x")]))).toEqual(["x", "x"]);
  });

  it("does not queue a repeat of a message that is already waiting", () => {
    const state = run([bad("1"), bad("2"), bad("3"), ok("w"), ok("w")]);
    expect(state.waiting).toHaveLength(1);
  });

  it("keeps the waiting list short", () => {
    const actions = [bad("1"), bad("2"), bad("3"), ...Array.from({ length: 30 }, (_, i) => ok(`w${i}`))];
    const state = run(actions);
    expect(state.waiting).toHaveLength(MAX_WAITING_TOASTS);
    expect(state.waiting.at(-1)?.message).toBe("w29");
    expect(state.waiting[0]?.message).toBe("w10");
  });

  it("dismisses by id, ignores unknown ids and keeps the same state object then", () => {
    const state = run([ok("a"), ok("b")]);
    expect(messages(toastReducer(state, { type: "dismiss", id: state.visible[0]?.id ?? 0 }))).toEqual(["b"]);
    expect(toastReducer(state, { type: "dismiss", id: 999 })).toBe(state);
  });

  it("clears everything but keeps counting ids", () => {
    const state = run([ok("a"), bad("b"), { type: "clear" }, ok("c")]);
    expect(messages(state)).toEqual(["c"]);
    expect(state.visible[0]?.id).toBe(3);
  });
});
