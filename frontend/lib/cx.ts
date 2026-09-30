/**
 * Join class names, dropping the falsy ones.
 *
 * The whole of what this app needs from `clsx`, in five lines, so that a
 * dependency does not have to be added to render a conditional border.
 */
export function cx(
  ...parts: Array<string | false | null | undefined>
): string {
  return parts.filter(Boolean).join(" ");
}
