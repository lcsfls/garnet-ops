import { Link } from "@tanstack/react-router";
import { cn } from "../lib/cn.ts";

/** A repository's name, leading to its page (scan and patch history). */
export function RepositoryLink({ id, name, className }: { id: string; name: string; className?: string }) {
  return (
    <Link to="/repositories/$id" params={{ id }} className={cn("hover:underline", className)}>
      {name}
    </Link>
  );
}
