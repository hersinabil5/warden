export function when(iso: string): string {
  if (!iso || iso.startsWith("0001-")) return "—";
  return new Date(iso).toLocaleString();
}

export function ago(iso: string): string {
  if (!iso || iso.startsWith("0001-")) return "—";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : "something went wrong";
}
