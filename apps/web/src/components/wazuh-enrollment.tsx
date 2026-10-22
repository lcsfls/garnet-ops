import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { toQuery } from "../lib/search.ts";
import type { XdrConnectionResponse, XdrEnrollment } from "../lib/types.ts";
import { Alert } from "./ui/alert.tsx";
import { Checkbox } from "./ui/checkbox.tsx";
import { CopyButton } from "./ui/copy-button.tsx";
import { Dialog } from "./ui/dialog.tsx";
import { Field, FormField, FormRow } from "./ui/field.tsx";
import { Select } from "./ui/select.tsx";

const OS_OPTIONS = ["debian", "rhel", "suse", "windows", "macos"] as const;
const ARCH_OPTIONS = ["amd64", "arm64"] as const;
/** Where the official instructions live; opened only when a person clicks. */
const WAZUH_AGENT_DOCS = "https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html";

/** Waits for typing to pause before the value is used for a request. */
function useDebounced<T>(value: T, ms = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(timer);
  }, [value, ms]);
  return debounced;
}

/** Whether a Wazuh connection exists, for the places that offer the helper only then. */
export function useWazuhConnected(): boolean {
  const status = useQuery({
    queryKey: ["xdr-status"],
    queryFn: () => api<{ connected: boolean }>("/xdr/status"),
    staleTime: 60_000,
  });
  return status.data?.connected === true;
}

/**
 * The agent enrollment helper (ADR 0015): the official Wazuh installation commands with the
 * address of the customer's manager. GarnetOps ships no agent; the commands download Wazuh from
 * packages.wazuh.com when the admin runs them. An enrollment password is never an input here: a
 * marked placeholder stands where it goes.
 */
export function EnrollmentHelper({ idPrefix = "enroll" }: { idPrefix?: string }) {
  const { t } = useTranslation();
  const [os, setOs] = useState<(typeof OS_OPTIONS)[number]>("debian");
  const [arch, setArch] = useState<(typeof ARCH_OPTIONS)[number]>("amd64");
  const [group, setGroup] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState(false);
  const debouncedGroup = useDebounced(group.trim());
  const debouncedName = useDebounced(name.trim());

  const connection = useQuery({
    queryKey: ["xdr-connection"],
    queryFn: () => api<XdrConnectionResponse>("/xdr/connection"),
  });
  const known = Boolean(connection.data?.connection?.managerVersion);
  const result = useQuery({
    queryKey: [
      "xdr-enrollment",
      os,
      arch,
      debouncedGroup,
      debouncedName,
      password,
      connection.data?.connection?.managerVersion,
    ],
    queryFn: () =>
      api<XdrEnrollment>(
        `/xdr/enrollment${toQuery({
          os,
          arch,
          group: debouncedGroup || undefined,
          name: debouncedName || undefined,
          password: password ? "1" : undefined,
        })}`,
      ),
    enabled: known,
    retry: false,
  });
  const error = result.error instanceof ApiError ? result.error : null;
  const data = result.data;
  const all = data ? data.steps.map((s) => s.text).join("\n") : "";

  return (
    <div className="grid gap-4">
      <FormRow columns={2} from="md">
        <FormField id={`${idPrefix}-os`} label={t("xdr.enrollOs")}>
          {(control) => (
            <Select {...control} value={os} onChange={(e) => setOs(e.currentTarget.value as typeof os)}>
              {OS_OPTIONS.map((o) => (
                <option key={o} value={o}>
                  {t(`xdr.enrollOsOption.${o}`)}
                </option>
              ))}
            </Select>
          )}
        </FormField>
        <FormField id={`${idPrefix}-arch`} label={t("xdr.enrollArch")}>
          {(control) => (
            <Select {...control} value={arch} onChange={(e) => setArch(e.currentTarget.value as typeof arch)}>
              {ARCH_OPTIONS.map((o) => (
                <option key={o} value={o}>
                  {t(`xdr.enrollArchOption.${o}`)}
                </option>
              ))}
            </Select>
          )}
        </FormField>
        <Field
          id={`${idPrefix}-group`}
          label={t("xdr.enrollGroup")}
          hint={t("xdr.enrollGroupHint")}
          value={group}
          onChange={(e) => setGroup(e.currentTarget.value)}
          placeholder="default"
          maxLength={200}
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          className="font-mono text-sm"
        />
        <Field
          id={`${idPrefix}-name`}
          label={t("xdr.enrollName")}
          hint={t("xdr.enrollNameHint")}
          value={name}
          onChange={(e) => setName(e.currentTarget.value)}
          maxLength={200}
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          className="font-mono text-sm"
        />
      </FormRow>
      <label className="flex items-start gap-2.5">
        <Checkbox
          className="mt-1"
          checked={password}
          onChange={(e) => setPassword(e.currentTarget.checked)}
        />
        <span>
          {t("xdr.enrollPassword")}
          <span className="block text-sm text-muted-foreground">{t("xdr.enrollPasswordHint")}</span>
        </span>
      </label>

      {!known && connection.data ? <Alert tone="info">{t("xdr.enrollNotSynced")}</Alert> : null}
      {error?.code === "not-synced" ? <Alert tone="info">{t("xdr.enrollNotSynced")}</Alert> : null}
      {error && error.code !== "not-synced" ? (
        <Alert tone="error">{error.status === 422 ? t("xdr.enrollInvalid") : t("errors.actionFailed")}</Alert>
      ) : null}

      {data ? (
        <div className="grid gap-3" data-testid="enrollment-output">
          <p className="text-sm text-muted-foreground">
            {t("xdr.enrollManager", { manager: data.manager })}{" "}
            {data.addressFromApi ? t("xdr.enrollManagerFromApi") : ""}
          </p>
          <p className="text-sm text-muted-foreground">
            {t("xdr.enrollVersion", { version: data.packageVersion ?? data.managerVersion })}
          </p>
          {data.preview ? <Alert tone="info">{t("xdr.enrollPreview")}</Alert> : null}
          <p className="text-sm text-muted-foreground">{t("xdr.enrollRootNote")}</p>
          {data.steps.map((step) => (
            <div key={step.id} className="grid gap-1.5">
              <span className="text-sm font-medium">{t(`xdr.enrollStep.${step.id}`)}</span>
              {/* Text only: the commands are shown, never run, and nothing in them is a link. */}
              <pre
                data-step={step.id}
                className="overflow-x-auto rounded-md border bg-muted px-3 py-2 font-mono text-[13px] leading-relaxed"
              >
                {step.text}
              </pre>
            </div>
          ))}
          <div className="flex flex-wrap items-center gap-3">
            <CopyButton text={all} />
            <a
              href={WAZUH_AGENT_DOCS}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-sm text-primary-text underline-offset-4 hover:underline"
            >
              <ExternalLink aria-hidden="true" className="size-3.5" />
              {t("xdr.enrollDocs")}
            </a>
          </div>
          {data.passwordPlaceholder ? (
            <Alert tone="info">
              {t("xdr.enrollPasswordReplace", { placeholder: "<ENROLLMENT_PASSWORD>" })}
            </Alert>
          ) : null}
          <p className="text-sm text-muted-foreground">{t("xdr.enrollAfter")}</p>
        </div>
      ) : null}
      <p className="text-sm text-muted-foreground">{t("xdr.enrollLicense")}</p>
    </div>
  );
}

/** The helper in a dialog, for the XDR page. */
export function EnrollmentDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t("xdr.enrollTitle")}
      description={t("xdr.enrollDescription")}
    >
      <EnrollmentHelper idPrefix="enroll-dialog" />
    </Dialog>
  );
}
