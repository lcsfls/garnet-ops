import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "../../lib/toast.ts";
import { Button } from "./button.tsx";

/** Copies text to the clipboard and confirms it for two seconds. */
export function CopyButton({ text }: { text: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="outline"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
        } catch {
          // The browser refused (no permission, or not a secure page): say so instead of nothing.
          toast.error(t("toast.copyFailed"));
          return;
        }
        setCopied(true);
        // A screen reader does not hear the button's label change; the toast is announced.
        toast.success(t("toast.copied"));
        setTimeout(() => setCopied(false), 2000);
      }}
    >
      {copied ? (
        <Check aria-hidden="true" className="size-4" />
      ) : (
        <Copy aria-hidden="true" className="size-4" />
      )}
      {copied ? t("common.copied") : t("common.copy")}
    </Button>
  );
}
