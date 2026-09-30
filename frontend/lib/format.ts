/**
 * Formatting for the things a reviewer has to be able to quote.
 *
 * Every formatter here pins both the locale and the zone. The analysis window
 * is a fixed pair of instants and the whole product's argument depends on
 * events being in the right order relative to it, so rendering a timestamp in
 * whatever zone the server or the reader happens to be in would be a silent
 * way to make a ghost-access timeline read wrong. UTC, always, and the zone is
 * stated in the output rather than implied.
 */

const LOCALE = "en-GB";

/** `2026-09-29T06:00:00Z` → `29 Sep 2026, 06:00 UTC`. */
export function formatStamp(value: string | null): string {
  if (!value) return "—";
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) return value;
  return `${at.toLocaleString(LOCALE, {
    timeZone: "UTC",
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  })} UTC`;
}

/** `2026-09-29T06:00:00Z` → `2026-09-29`. Sorts and aligns; used in columns. */
export function formatDate(value: string | null): string {
  if (!value) return "—";
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) return value;
  return at.toISOString().slice(0, 10);
}

/**
 * The dataset's short name.
 *
 * Twelve characters, matching what the API and the tests call the prefix. The
 * full hash is never more useful to a reader than the prefix -- what it is for
 * is confirming two views are talking about the same ingest -- and a 64-char
 * hex string on the page would be the loudest thing on it.
 */
export function hashPrefix(contentHash: string): string {
  return contentHash.slice(0, 12);
}

/** Two digits, so the register's margin stays a column rather than a ragged edge. */
export function exhibitNumber(index: number): string {
  return String(index + 1).padStart(2, "0");
}
