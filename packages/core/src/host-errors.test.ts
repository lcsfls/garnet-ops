import { describe, expect, it } from "vitest";
import {
  HOST_ERRORS,
  HostError,
  type HostErrorCode,
  hostErrorMessage,
  parseHostError,
} from "./host-errors.ts";

describe("host errors", () => {
  it("maps every stored text back to its code", () => {
    for (const code of Object.keys(HOST_ERRORS) as HostErrorCode[]) {
      const text = hostErrorMessage(code, { seconds: 60, limit: 16 });
      expect(parseHostError(text)?.code, code).toBe(code);
    }
  });

  it("recovers the parameters of a text", () => {
    expect(parseHostError(hostErrorMessage("inventoryTimeout", { seconds: 60 }))).toEqual({
      code: "inventoryTimeout",
      params: { seconds: "60" },
    });
    expect(parseHostError(hostErrorMessage("inventoryTooLarge", { limit: 16 }))?.params).toEqual({
      limit: "16",
    });
  });

  it("does not know other texts", () => {
    expect(parseHostError("ssh: connect to host 192.0.2.1 port 22: Connection refused")).toBeNull();
  });

  it("carries the safe text as its message", () => {
    const error = new HostError("hostUnreachable");
    expect(error.message).toBe(HOST_ERRORS.hostUnreachable);
    expect(error.code).toBe("hostUnreachable");
  });
});
