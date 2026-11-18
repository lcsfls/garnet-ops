import type { InventoryKind, InventoryTokenScope } from "@garnetops/core/inventory";

/** The inventory (ADR 0053) as the API answers it. */
export interface InventorySoftware {
  name: string;
  version: string;
}
export interface InventorySystem {
  id: string;
  key: string;
  name: string;
  kind: InventoryKind;
  environment: string | null;
  notes: string | null;
  tags: string[];
  source: "manual" | "script";
  reportedAt: string | null;
  updatedAt: string;
  /** The whole list on a system's own answer; the first few in the list of systems. */
  software: InventorySoftware[];
}
export type InventoryRow = InventorySystem & { softwareCount: number };

export interface InventoryTokenRow {
  id: string;
  label: string;
  prefix: string;
  scope: InventoryTokenScope;
  createdAt: string;
  lastUsedAt: string | null;
  createdBy: string | null;
}

/** One place a piece of software runs, from any source GarnetOps knows. */
export interface SoftwareHit {
  source: "inventory" | "host" | "container" | "repository";
  id: string;
  system: string | null;
  detail: string | null;
  name: string | null;
  version: string | null;
  checked: boolean;
}
