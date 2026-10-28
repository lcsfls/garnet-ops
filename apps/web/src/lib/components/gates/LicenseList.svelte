<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import Button from "../ui/Button.svelte";
  import Field from "../ui/Field.svelte";

  /** The licenses the "license-denied" rule matches, as a comma or space separated list. */
  let { value, pending, onSave }: { value: string[]; pending: boolean; onSave: (list: string[]) => void } =
    $props();

  // The field starts from the stored list and is then the user's to edit, like an uncontrolled input.
  // svelte-ignore state_referenced_locally
  const initial = value.join(", ");

  function submit(event: SubmitEvent) {
    event.preventDefault();
    const raw = String(new FormData(event.currentTarget as HTMLFormElement).get("licenses") ?? "");
    onSave([
      ...new Set(
        raw
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
      ),
    ]);
  }
</script>

<form class="grid gap-2" onsubmit={submit}>
  <Field
    label={t("gates.deniedLicenses")}
    hint={t("gates.deniedLicensesHint")}
    name="licenses"
    value={initial}
    spellcheck={false}
    class="font-mono text-sm"
  />
  <div>
    <Button type="submit" variant="outline" disabled={pending}>{t("gates.saveLicenses")}</Button>
  </div>
</form>
