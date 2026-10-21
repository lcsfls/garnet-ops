import type { Role } from "./index.ts";

/**
 * Who may grant which role and manage whom (ADR 0009). Owners manage everyone; admins
 * manage members and viewers only, so an admin can never create or touch an owner or admin.
 */
export function canAssignRole(actor: Role, role: Role): boolean {
  if (actor === "owner") return true;
  if (actor === "admin") return role === "member" || role === "viewer";
  return false;
}

/** Whether `actor` may change the role of, or remove, someone who currently has `target`. */
export function canManageMember(actor: Role, target: Role): boolean {
  return canAssignRole(actor, target);
}
