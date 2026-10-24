/**
 * The drawn device: the chevron of the mark's `>_` repeated outward as fourteen nested
 * hairline chevrons, in the colour of the text at stepped opacities (0.28 / 0.16 / 0.09).
 * Each chevron is the right half of a diamond around one centre left of the panel, so the
 * arms stay parallel and enter from the panel's left edge. The strokes do not scale with
 * the panel (`non-scaling-stroke`): 1.2 px at any size. It crosses the login panel and
 * nothing else; it is decorative and hidden from assistive technology.
 */
const COUNT = 14;
const CX = -40;
const CY = 450;
const R0 = 104;
const STEP = 42;

export function PromptLines() {
  return (
    <svg
      aria-hidden="true"
      focusable="false"
      viewBox="0 0 800 900"
      preserveAspectRatio="xMidYMid slice"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.2}
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{
        position: "absolute",
        inset: 0,
        width: "100%",
        height: "100%",
        color: "var(--foreground)",
        pointerEvents: "none",
      }}
    >
      {Array.from({ length: COUNT }, (_, i) => {
        const r = R0 + i * STEP;
        return (
          <path
            key={i}
            d={`M${CX} ${CY - r}L${CX + r} ${CY}L${CX} ${CY + r}`}
            vectorEffect="non-scaling-stroke"
            opacity={i % 3 === 0 ? 0.28 : i % 3 === 1 ? 0.16 : 0.09}
          />
        );
      })}
    </svg>
  );
}
