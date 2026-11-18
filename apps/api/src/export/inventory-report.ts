import { type Messages, resources } from "@garnetops/i18n";
import { dayTime, fill, type ReportContext } from "./findings-report.ts";
import type { Column, Report } from "./table.ts";

/** An inventory system as the export reads it (ADR 0053). Everything is typed or reported text; every writer escapes it. */
export interface InventoryExportSystem {
  key: string;
  name: string;
  kind: string;
  environment: string | null;
  notes: string | null;
  tags: string[];
  source: "manual" | "script";
  reportedAt: Date | null;
  updatedAt: Date;
  software: { name: string; version: string }[];
}

/** The inventory as a report: one row per system and piece of software (a system without software has one row). */
export function inventoryReport(
  systems: InventoryExportSystem[],
  context: ReportContext,
  maxRows: number,
): Report {
  const m: Messages = resources[context.language].translation;
  const e = m.export;
  const x = m.inventory.export;
  const columns: Column[] = [
    { label: m.inventory.columnSystem, width: 20 },
    { label: m.inventory.fieldKey, width: 16, wide: true },
    { label: m.inventory.columnKind, width: 10 },
    { label: m.inventory.fieldEnvironment, width: 10 },
    { label: x.columnSoftware, width: 20 },
    { label: x.columnVersion, width: 12 },
    { label: m.inventory.fieldTags, width: 14, wide: true },
    { label: m.inventory.columnSource, width: 8, wide: true },
    { label: x.columnChanged, width: 13 },
    { label: m.inventory.fieldNotes, width: 30, wide: true },
  ];
  const kinds = m.inventory.kind as Record<string, string>;
  const now = context.now ?? new Date();
  const rows: Report["rows"] = [];
  let total = 0;
  for (const system of systems) {
    const head = [system.name, system.key, kinds[system.kind] ?? system.kind, system.environment];
    const tail = [
      system.tags.join(", ") || null,
      m.inventory.source[system.source],
      dayTime(system.reportedAt ?? system.updatedAt, context.timeZone),
      system.notes,
    ];
    const software = system.software.length ? system.software : [{ name: null, version: null }];
    for (const item of software) {
      total++;
      if (rows.length < maxRows) rows.push([...head, item.name, item.version || null, ...tail]);
    }
  }
  return {
    title: x.title,
    meta: [
      fill(e.created, { when: dayTime(now, context.timeZone), zone: context.timeZone }),
      context.filters.length ? fill(e.filters, { filters: context.filters.join(", ") }) : x.noFilters,
      fill(x.count, { count: systems.length }),
      x.notChecked,
    ],
    columns,
    rows,
    note: rows.length < total ? fill(x.truncated, { shown: rows.length, total }) : undefined,
  };
}
