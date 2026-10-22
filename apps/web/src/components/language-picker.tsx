import { LANGUAGE_NAMES, LANGUAGES, type Language } from "@garnetops/i18n";
import { Languages } from "lucide-react";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { setLanguage } from "../lib/i18n.ts";
import { Select } from "./ui/select.tsx";

/** Explicit language choice; English is the default for everyone. */
export function LanguagePicker({ onChanged }: { onChanged?: (language: Language) => void }) {
  const { t, i18n } = useTranslation();
  const id = useId();
  return (
    <div className="flex items-center gap-1.5">
      <label htmlFor={id} className="text-muted-foreground">
        <Languages aria-hidden="true" className="size-4" />
        <span className="sr-only">{t("common.language")}</span>
      </label>
      <Select
        id={id}
        value={i18n.language}
        onChange={(e) => {
          const language = e.target.value as Language;
          void setLanguage(language);
          onChanged?.(language);
        }}
        className="h-9 text-sm"
      >
        {LANGUAGES.map((l) => (
          <option key={l} value={l} lang={l}>
            {LANGUAGE_NAMES[l]}
          </option>
        ))}
      </Select>
    </div>
  );
}
