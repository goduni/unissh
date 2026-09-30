import { useCallback, useLayoutEffect, useRef, useState } from "react";
import { visibleRows } from "./virtualRows";

/** The sticky header and the parent-directory row precede the virtual file rows. */
export function useVirtualRows(count: number, rowHeight: number, resetKey: unknown, error: string | null) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const headerRef = useRef<HTMLDivElement>(null);
  const rowsRef = useRef<HTMLDivElement>(null);
  const [viewport, setViewport] = useState({ top: 0, height: 0 });
  const measure = useCallback(() => {
    const el = scrollRef.current;
    const rows = rowsRef.current;
    if (!el || !rows) return;
    const top = el.getBoundingClientRect().top - rows.getBoundingClientRect().top;
    setViewport(old => old.top === top && old.height === el.clientHeight ? old : { top, height: el.clientHeight });
  }, []);

  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    if (headerRef.current) observer.observe(headerRef.current);
    measure();
    return () => observer.disconnect();
  }, [measure, rowHeight, error]);

  useLayoutEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
    measure();
  }, [resetKey, measure, error]);

  const reveal = (index: number) => {
    const el = scrollRef.current;
    const rows = rowsRef.current;
    if (!el || !rows) return;
    const header = headerRef.current?.getBoundingClientRect().height ?? 0;
    const origin = rows.getBoundingClientRect().top - el.getBoundingClientRect().top + el.scrollTop;
    const top = origin + index * rowHeight;
    if (top < el.scrollTop + header) el.scrollTop = Math.max(0, top - header);
    else if (top + rowHeight > el.scrollTop + el.clientHeight) el.scrollTop = top + rowHeight - el.clientHeight;
    measure();
  };

  return { scrollRef, headerRef, rowsRef, measure, reveal, ...visibleRows(count, rowHeight, viewport.top, viewport.height) };
}
