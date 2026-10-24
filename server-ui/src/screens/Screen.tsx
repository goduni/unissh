import type { ReactNode } from "react";

/**
 * The page of a screen: a vertical stack at 16 px. First the header row: the `h1` at 20 / 600 with tight tracking and
 * a balanced wrap, one muted sentence under it (14 px, at most 72 ch), the actions pushed right. One solid blue button
 * a screen stands here at most; every other action is an outline or a ghost. Then the screen's blocks, full width,
 * 16 px apart: a block needs no margin of its own between it and the next. The shell scrolls the whole document and
 * pads the page. The zero-knowledge boundary is said once, by the screen's `ZkBanner`, not beside the title.
 */
export function Screen({
  title,
  sub,
  actions,
  children,
}: {
  title: string;
  sub?: string;
  /** @deprecated Ignored: every zero-knowledge screen says so in its `ZkBanner`. */
  zk?: boolean;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16, minWidth: 0 }}>
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "8px 16px",
        }}
      >
        <div style={{ display: "grid", gap: 4, minWidth: 0 }}>
          <h1
            style={{
              margin: 0,
              fontSize: 20,
              fontWeight: 600,
              lineHeight: 1.4,
              letterSpacing: "-0.025em",
              textWrap: "balance",
            }}
          >
            {title}
          </h1>
          {sub ? (
            <p
              style={{
                margin: 0,
                maxWidth: "72ch",
                color: "var(--muted-foreground)",
                fontSize: 14,
                lineHeight: "20px",
              }}
            >
              {sub}
            </p>
          ) : null}
        </div>
        {actions ? (
          <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>{actions}</div>
        ) : null}
      </div>
      {children}
    </div>
  );
}

