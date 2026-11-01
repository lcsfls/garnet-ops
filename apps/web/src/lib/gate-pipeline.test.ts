import { describe, expect, it } from "vitest";
import { pipelineStep, workflowFile } from "./gate-pipeline.ts";

describe("gate pipeline", () => {
  it("names this server and reads the token from the CI secret", () => {
    const step = pipelineStep("https://garnetops.example.com");
    expect(step).toContain("GARNETOPS_URL: https://garnetops.example.com");
    // The forge fills in the secret; in the YAML it stays a ${{ }} expression.
    expect(step).toContain(`GARNETOPS_TOKEN: \${{ secrets.GARNETOPS_TOKEN }}`);
  });

  it("wraps the step in a workflow that runs on pull requests, indented as YAML needs", () => {
    const file = workflowFile("https://garnetops.example.com");
    expect(file.split("\n").slice(0, 7)).toEqual([
      "name: GarnetOps quality gate",
      "on:",
      "  pull_request:",
      "jobs:",
      "  gate:",
      "    runs-on: ubuntu-latest",
      "    steps:",
    ]);
    expect(file).toContain("\n      - name: GarnetOps quality gate\n        env:\n          GARNETOPS_URL:");
    expect(file).toContain("\n        run: |\n          auth=");
  });
});
