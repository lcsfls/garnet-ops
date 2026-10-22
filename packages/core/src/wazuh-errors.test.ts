import { describe, expect, it } from "vitest";
import {
  parseWazuhError,
  WAZUH_ERRORS,
  WazuhError,
  type WazuhErrorCode,
  wazuhErrorMessage,
} from "./wazuh-errors.ts";

describe("Wazuh error texts", () => {
  it("map back to their code and parameters", () => {
    const e = new WazuhError("unreachable", { endpoint: "indexer" });
    expect(e.message).toBe("The Wazuh indexer could not be reached.");
    expect(parseWazuhError(e.message)).toEqual({ code: "unreachable", params: { endpoint: "indexer" } });
    const big = new WazuhError("responseTooLarge", { endpoint: "manager", limit: 8 });
    expect(parseWazuhError(big.message)).toEqual({
      code: "responseTooLarge",
      params: { endpoint: "manager API", limit: "8" },
    });
  });

  it("every text is distinguishable: each code parses back to itself", () => {
    for (const code of Object.keys(WAZUH_ERRORS) as WazuhErrorCode[]) {
      const message = wazuhErrorMessage(code, {
        endpoint: "manager API",
        limit: 8,
        minutes: 5,
        version: "3.13.6",
      });
      expect(parseWazuhError(message)?.code, code).toBe(code);
    }
  });

  it("an error can be attributed to an endpoint afterwards", () => {
    const generic = new WazuhError("timeout");
    const attributed = generic.forEndpoint("manager");
    expect(attributed.message).toBe("The Wazuh manager API did not answer in time.");
    expect(attributed.endpoint).toBe("manager");
  });

  it("do not know an unknown text", () => {
    expect(parseWazuhError("Something else")).toBeNull();
  });
});
