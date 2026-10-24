import type { CSSProperties, KeyboardEvent as ReactKeyboardEvent, ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { IconName } from "./icons";
import { MONO } from "../theme/tokens";
import { Btn, EmptyState, ErrorCard, Missing, Skeleton, SummaryLine } from "./primitives";

/** Extra room before a left-aligned column that follows a right-aligned one: 12 px of gap alone reads as one cell. */
const AFTER_RIGHT = 24;

export interface Column<T> {
  key: string;
  label: ReactNode;
  /** CSS grid track, e.g. "2fr", "90px", "1.5fr". */
  width: string;
  align?: "left" | "right" | "center";
  /** A column of figures: right-aligned, mono at 12 px, head and cell alike. */
  numeric?: boolean;
  /** The cell. Returning null, undefined or "" shows a muted em dash. */
  render: (row: T) => ReactNode;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, i: number) => string;
  onRowClick?: (row: T) => void;
  loading?: boolean;
  error?: string | null;
  /** The HTTP status of `error` (0 for no connection): the failure box says which failure it is. */
  errorStatus?: number;
  onRetry?: () => void;
  empty?: {
    title: string;
    hint?: string;
    icon?: IconName;
    actionLabel?: string;
    onAction?: () => void;
  };
  more?: { hasMore: boolean; loading?: boolean; onMore: () => void };
  /**
   * The summary line above the head. `true`: "in all: N", N being `total` or
   * the rows counted. A node: the line's own parts (SummaryCount, SummaryPart).
   */
  summary?: ReactNode;
  /** How many the list holds in all, when `rows` is one page of it. */
  total?: number;
  /**
   * The table stands inside a Card under its head: no frame of its own, and
   * an empty list is one compact row of that card.
   */
  bare?: boolean;
  /** Below this width (px) the table scrolls sideways instead of squeezing. Default 640. */
  minWidth?: number;
  /** The table's accessible name. */
  ariaLabel?: string;
}

/** Is a rendered cell "no value"? */
function isMissing(v: ReactNode): boolean {
  return v === null || v === undefined || v === "" || v === false;
}

function alignOf<T>(c: Column<T>): "left" | "right" | "center" {
  return c.numeric ? "right" : (c.align ?? "left");
}

/** The label style of the head row. */
const HEAD: CSSProperties = {
  fontSize: 11,
  fontWeight: 600,
  letterSpacing: "0.05em",
  textTransform: "uppercase",
  color: "var(--muted-foreground)",
};

/**
 * A ruled table on a card: the head row 28 px on --rail in the label style,
 * rows of at least 32 px divided by --rule (hover at half --elevated), the
 * first column 16 px in. Loading draws skeleton rows; a failure with nothing to
 * show is the red box in the table's place; an empty list is the dashed box.
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  loading,
  error,
  errorStatus,
  onRetry,
  empty,
  more,
  summary,
  total,
  bare,
  minWidth = 640,
  ariaLabel,
}: DataTableProps<T>) {
  const { t } = useTranslation();
  const template = columns.map((c) => c.width).join(" ");
  const firstLoad = !!loading && rows.length === 0;
  // A left-aligned column right after a right-aligned one (figures) gets room before it.
  const lead = columns.map((c, i) =>
    i > 0 && alignOf(columns[i - 1]) === "right" && alignOf(c) === "left" ? AFTER_RIGHT : 0,
  );

  // Nothing to show: the failure, or the empty state, stands in the table's place.
  if (error && rows.length === 0) {
    return <ErrorCard message={error} status={errorStatus} onRetry={onRetry} retrying={loading} band={bare} />;
  }
  if (!loading && rows.length === 0 && empty) {
    return (
      <EmptyState
        icon={empty.icon}
        title={empty.title}
        hint={empty.hint}
        actionLabel={empty.actionLabel}
        onAction={empty.onAction}
        compact={bare}
        flat={bare}
      />
    );
  }

  const frame: CSSProperties = bare
    ? {}
    : {
        background: "var(--card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        boxShadow: "var(--elev-card)",
        overflow: "hidden",
      };

  const grid: CSSProperties = {
    display: "grid",
    gridTemplateColumns: template,
    columnGap: 12,
    alignItems: "center",
    padding: "0 16px",
  };

  // Each cell keeps 3 px around its content so a focus ring inside is not clipped.
  const cellStyle = (c: Column<T>, i: number): CSSProperties => {
    const align = alignOf(c);
    return {
      minWidth: 0,
      overflow: "hidden",
      // Longhands, since the left one varies by column (React warns on a shorthand beside its own part).
      paddingTop: 3,
      paddingRight: 3,
      paddingBottom: 3,
      paddingLeft: 3 + lead[i],
      margin: -3,
      textAlign: align,
      display: align === "left" ? undefined : "flex",
      alignItems: align === "left" ? undefined : "center",
      justifyContent: align === "right" ? "flex-end" : align === "center" ? "center" : undefined,
      fontFamily: c.numeric ? MONO : undefined,
      fontSize: c.numeric ? 12 : undefined,
    };
  };

  const rowStyle: CSSProperties = {
    ...grid,
    minHeight: 32,
    paddingTop: 4,
    paddingBottom: 4,
    borderBottom: "1px solid var(--rule)",
  };

  const onRowKey = (e: ReactKeyboardEvent, row: T) => {
    // Only the row's own keys; a button inside it keeps Enter and Space.
    if (!onRowClick || e.target !== e.currentTarget) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onRowClick(row);
    }
  };

  const showSummary = summary !== undefined && summary !== null && summary !== false;

  return (
    <div style={frame}>
      {showSummary ? (
        summary === true ? (
          <SummaryLine count={total ?? rows.length} loading={firstLoad} />
        ) : (
          <SummaryLine loading={firstLoad}>{summary}</SummaryLine>
        )
      ) : null}

      {error ? (
        <div style={{ borderBottom: "1px solid var(--rule)" }}>
          <ErrorCard message={error} status={errorStatus} onRetry={onRetry} retrying={loading} band />
        </div>
      ) : null}

      <div style={{ overflowX: "auto" }}>
        <div role="table" aria-label={ariaLabel} aria-busy={loading || undefined} style={{ minWidth }}>
          <div
            role="row"
            style={{
              ...grid,
              ...HEAD,
              height: 28,
              background: "var(--rail)",
              borderBottom: "1px solid var(--rule)",
            }}
          >
            {columns.map((c, i) => (
              <span
                key={c.key}
                role="columnheader"
                style={{
                  minWidth: 0,
                  overflow: "hidden",
                  paddingLeft: lead[i] || undefined,
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  textAlign: alignOf(c),
                }}
              >
                {c.label}
              </span>
            ))}
          </div>

          <div role="rowgroup">
            {firstLoad
              ? Array.from({ length: 5 }, (_, i) => (
                  <div key={`skeleton-${i}`} role="row" className="dt-row dt-skeleton-row" style={rowStyle}>
                    {columns.map((c, i) => (
                      <span key={c.key} role="cell" style={cellStyle(c, i)}>
                        <Skeleton width="75%" height={14} />
                      </span>
                    ))}
                  </div>
                ))
              : rows.map((row, i) => (
                  <div
                    key={rowKey(row, i)}
                    role="row"
                    className={onRowClick ? "dt-row clickable" : "dt-row"}
                    tabIndex={onRowClick ? 0 : undefined}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                    onKeyDown={onRowClick ? (e) => onRowKey(e, row) : undefined}
                    style={rowStyle}
                  >
                    {columns.map((c, i) => {
                      const v = c.render(row);
                      return (
                        <span key={c.key} role="cell" style={cellStyle(c, i)}>
                          {isMissing(v) ? <Missing /> : v}
                        </span>
                      );
                    })}
                  </div>
                ))}
          </div>
        </div>
      </div>

      {more && more.hasMore ? (
        <div
          style={{
            display: "flex",
            justifyContent: "center",
            padding: "8px 16px",
            borderTop: "1px solid var(--rule)",
          }}
        >
          <Btn size="sm" variant="outline" loading={more.loading} onClick={more.onMore}>
            {t("common.more")}
          </Btn>
        </div>
      ) : null}
    </div>
  );
}
