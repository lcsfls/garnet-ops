import { describe, expect, it } from "vitest";
import {
  parseUnifiError,
  UNIFI_ERRORS,
  UnifiError,
  type UnifiErrorCode,
  unifiErrorMessage,
} from "./unifi-errors.ts";

describe("UniFi error texts", () => {
  it("map every stored text back to its code", () => {
    for (const code of Object.keys(UNIFI_ERRORS) as UnifiErrorCode[]) {
      const params = { limit: 4, minutes: 10 };
      const parsed = parseUnifiError(unifiErrorMessage(code, params));
      expect(parsed?.code, code).toBe(code);
    }
  });

  it("fill and recover parameters", () => {
    const message = unifiErrorMessage("responseTooLarge", { limit: 4 });
    expect(message).toBe("A console answer is larger than the 4 MB limit.");
    expect(parseUnifiError(message)).toEqual({ code: "responseTooLarge", params: { limit: "4" } });
  });

  it("do not know texts of other versions", () => {
    expect(parseUnifiError("Something else")).toBeNull();
  });

  it("carry the message of the code and the HTTP status", () => {
    const error = new UnifiError("keyRejected", {}, 401);
    expect(error.message).toBe(UNIFI_ERRORS.keyRejected);
    expect(error.status).toBe(401);
    expect(error).toBeInstanceOf(Error);
  });

  it("never mention a key, a password or a header name", () => {
    for (const text of Object.values(UNIFI_ERRORS)) {
      expect(text).not.toMatch(/x-api-key|authorization|cookie|csrf/i);
    }
  });
});
