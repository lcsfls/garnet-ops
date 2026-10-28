/** Up to two initials of the user's name, for the avatar. */
export function initialsOf(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  const letters = parts.length > 1 ? [parts[0], parts[parts.length - 1]] : parts;
  return letters.map((p) => [...(p ?? "")][0]?.toUpperCase() ?? "").join("") || "?";
}
