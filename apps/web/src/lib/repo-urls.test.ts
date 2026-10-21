import { describe, expect, test } from "vitest";
import { parseUrlList } from "./repo-urls.ts";

describe("parseUrlList", () => {
  test("one address per line, trimmed, blank lines and repeats dropped", () => {
    const text =
      "  https://git.example.com/team/a.git\r\n\nhttps://git.example.com/team/b.git  \n\n" +
      "https://git.example.com/team/a.git\n";
    expect(parseUrlList(text)).toEqual([
      "https://git.example.com/team/a.git",
      "https://git.example.com/team/b.git",
    ]);
  });

  test("an empty or blank list has no addresses", () => {
    expect(parseUrlList("")).toEqual([]);
    expect(parseUrlList(" \n\t\n")).toEqual([]);
  });
});
