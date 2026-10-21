import { describe, expect, test } from "vitest";
import { ROLES } from "./index.ts";
import { canAssignRole, canManageMember } from "./team.ts";

describe("team permissions", () => {
  test("owners grant and manage every role", () => {
    for (const role of ROLES) {
      expect(canAssignRole("owner", role)).toBe(true);
      expect(canManageMember("owner", role)).toBe(true);
    }
  });

  test("admins only grant and manage members and viewers", () => {
    expect(ROLES.filter((r) => canAssignRole("admin", r))).toEqual(["member", "viewer"]);
    expect(ROLES.filter((r) => canManageMember("admin", r))).toEqual(["member", "viewer"]);
  });

  test("members and viewers manage nobody", () => {
    for (const actor of ["member", "viewer"] as const) {
      for (const role of ROLES) {
        expect(canAssignRole(actor, role)).toBe(false);
        expect(canManageMember(actor, role)).toBe(false);
      }
    }
  });
});
