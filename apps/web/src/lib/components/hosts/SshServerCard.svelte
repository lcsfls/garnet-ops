<script lang="ts">
  import type { SshdSetting } from "@garnetops/core/sshd";
  import { formatRelative } from "../../format.ts";
  import type { HostSsh } from "../../hosts.ts";
  import { t } from "../../i18n.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";
  import Facts, { type Fact } from "../websites/Facts.svelte";

  /**
   * The host's SSH server (ADR 0037, addendum "SSH server"): what the agent read from files (the server, its package, the C library,
   * PAM and the global values of a few settings) and the configuration findings, worst first. Report-only: nothing here changes a
   * vulnerability, a grade or a gate, and the card says so. The one exception is sshole while the vulnerability database does not
   * list it: it counts in the menu's number for agents (GET /hosts/attention).
   */
  let { ssh }: { ssh: HostSsh } = $props();
  const settings = $derived(ssh.server === "openssh" && ssh.config?.read ? ssh.config.settings : null);

  /** "no", "yes (OpenSSH's default)", plus what Match blocks set. */
  const setting = (label: string, s: SshdSetting | undefined): Fact => ({
    label,
    text: s ? s.value : null,
    mono: true,
    note:
      [
        s?.default ? t("hosts.sshDefault") : null,
        s?.match.length ? t("hosts.sshInMatch", { values: s.match.join(", ") }) : null,
      ]
        .filter(Boolean)
        .join(" · ") || null,
  });
  const pamText = $derived(
    ssh.pam === true
      ? t("hosts.sshPamUsed")
      : ssh.pamLinked === false
        ? t("hosts.sshPamNotBuilt")
        : ssh.pam === false
          ? t("hosts.sshPamOff")
          : t("hosts.sshPamUnknown"),
  );
  const rows = $derived<Fact[]>([
    {
      label: t("hosts.sshServer"),
      text: t(`hosts.sshServerValue.${ssh.server}`),
      note: ssh.package ? `${ssh.package.name} ${ssh.package.version}` : null,
    },
    ...(ssh.program ? [{ label: t("hosts.sshProgram"), text: ssh.program, mono: true }] : []),
    { label: t("hosts.sshLibc"), text: t(`hosts.sshLibcValue.${ssh.libc}`) },
    ...(ssh.server === "openssh" ? [{ label: t("hosts.sshPam"), text: pamText }] : []),
    ...(settings
      ? [
          setting(t("hosts.sshPasswordAuthentication"), settings.passwordAuthentication),
          setting(t("hosts.sshPermitRootLogin"), settings.permitRootLogin),
          setting(t("hosts.sshPubkey"), settings.pubkeyAuthentication),
          setting(t("hosts.sshKbdInteractive"), settings.kbdInteractiveAuthentication),
          setting(t("hosts.sshEmptyPasswords"), settings.permitEmptyPasswords),
        ]
      : []),
    { label: t("hosts.packagesReported"), text: ssh.reportedAt ? formatRelative(ssh.reportedAt) : null },
  ]);
  const skipped = $derived(
    (ssh.config?.skipped ?? []).map((s) => `${s.path} (${t(`hosts.sshSkipReason.${s.reason}`)})`).join(", "),
  );
</script>

<Card>
  <div data-testid="host-ssh">
    <CardHeader title={t("hosts.sshTitle")} description={t("hosts.sshDescription")} />
    <Facts {rows} />
    <div class="grid gap-3 px-5 pb-5 text-sm">
      {#if ssh.server === "none"}
        <p class="text-muted-foreground">{t("hosts.sshNone")}</p>
      {:else if ssh.server === "dropbear"}
        <p class="text-muted-foreground">{t("hosts.sshDropbear")}</p>
      {:else if !settings}
        <p class="text-muted-foreground" data-testid="ssh-unreadable">
          {t("hosts.sshConfigUnreadable", { problem: ssh.config?.problem ?? "unreadable" })}
        </p>
      {:else}
        <p class="text-muted-foreground">
          {t("hosts.sshFiles", { count: ssh.config?.files.length ?? 0 })}{#if skipped}. {t("hosts.sshSkipped", { files: skipped })}{/if}
        </p>
        {#if ssh.findings.length === 0}
          <p>{t("hosts.sshNoFindings")}</p>
        {:else}
          <ul class="grid gap-3" data-testid="ssh-findings">
            {#each ssh.findings as f (f.rule)}
              <li class="grid gap-1 border-t pt-3 first:border-t-0 first:pt-0" data-rule={f.rule}>
                <div class="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <span class="font-medium">{t(`hosts.sshRules.${f.rule}.title`)}</span>
                </div>
                <p><span class="text-muted-foreground">{t("hosts.sshWhy")}:</span> {t(`hosts.sshRules.${f.rule}.why`)}</p>
                <p><span class="text-muted-foreground">{t("hosts.sshFix")}:</span> {t(`hosts.sshRules.${f.rule}.fix`)}</p>
                {#if f.scope === "match"}<p class="text-muted-foreground">{t("hosts.sshScopeMatch")}</p>{/if}
                {#if f.basis}
                  <p class="text-muted-foreground">
                    {f.basis === "version" ? t("hosts.sshBasisVersion") : t("hosts.sshBasisFinding")}
                  </p>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      {/if}
    </div>
  </div>
</Card>
