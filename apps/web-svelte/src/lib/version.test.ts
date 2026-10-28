import { describe, expect, it } from "vitest";
import { displayVersion } from "./version.ts";

describe("displayVersion", () => {
  it("labels 0.x releases as alpha", () => {
    expect(displayVersion("0.0.1", "Alpha")).toBe("0.0.1 Alpha");
    expect(displayVersion("0.4.2", "Alpha")).toBe("0.4.2 Alpha");
  });

  it("leaves other versions as they are", () => {
    expect(displayVersion("1.0.0", "Alpha")).toBe("1.0.0");
    expect(displayVersion("0.0.1-rc.1", "Alpha")).toBe("0.0.1-rc.1");
  });
});
