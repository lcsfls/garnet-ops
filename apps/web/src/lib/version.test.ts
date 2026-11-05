import { describe, expect, it } from "vitest";
import { displayVersion, releaseStage } from "./version.ts";

const labels = { alpha: "Alpha", beta: "Beta" };

describe("displayVersion", () => {
  it("labels 0.0.x releases as alpha and the other 0.x releases as beta", () => {
    expect(displayVersion("0.0.1", labels)).toBe("0.0.1 Alpha");
    expect(displayVersion("0.0.18", labels)).toBe("0.0.18 Alpha");
    expect(displayVersion("0.1.0", labels)).toBe("0.1.0 Beta");
    expect(displayVersion("0.4.2", labels)).toBe("0.4.2 Beta");
  });

  it("adds nothing from 1.0.0 on, or to a version of another shape", () => {
    expect(displayVersion("1.0.0", labels)).toBe("1.0.0");
    expect(displayVersion("0.0.1-rc.1", labels)).toBe("0.0.1-rc.1");
    expect(releaseStage("dev")).toBeNull();
  });
});
