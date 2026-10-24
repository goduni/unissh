/** The product's name beside the mark. A name, not copy: it is the same in every language. */
export const PRODUCT_NAME = "UniSSH";

/**
 * The mark: the shell prompt `>_`, drawn in 1.3 px round-capped strokes in the colour of the text (the chevron at full
 * strength, the underscore at 0.6) on a 22 px `--elevated` tile with 7 px corners. The app icon's violet gradient is
 * the client's; the admin never uses it.
 */
export function Mark({ size = 22 }: { size?: number }) {
  const glyph = Math.round(size * 0.64);
  return (
    <span
      aria-hidden="true"
      style={{
        display: "grid",
        flexShrink: 0,
        placeItems: "center",
        width: size,
        height: size,
        borderRadius: "var(--radius-md)",
        background: "var(--elevated)",
        color: "var(--foreground)",
      }}
    >
      <svg
        width={glyph}
        height={glyph}
        viewBox="0 0 14 14"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.3}
        strokeLinecap="round"
        strokeLinejoin="round"
        style={{ display: "block" }}
      >
        <path d="M3 3.5 6.5 7 3 10.5" />
        <path d="M8 10.8h3.3" opacity={0.6} />
      </svg>
    </span>
  );
}

/** The wordmark: the mark and "UniSSH" at 15 / 600 with tight tracking. */
export function Wordmark() {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 10,
        color: "var(--foreground)",
        fontSize: 15,
        fontWeight: 600,
        lineHeight: 1.25,
        letterSpacing: "-0.025em",
        whiteSpace: "nowrap",
      }}
    >
      <Mark />
      {PRODUCT_NAME}
    </span>
  );
}
