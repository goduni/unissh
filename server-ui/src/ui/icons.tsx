// Lucide-derived icon set (inner SVG paths, 24×24 viewBox, round caps). Render
// via <Icon name … />: 16 px beside a word, muted unless it says a state. Icons
// are decorative (hidden from assistive technology); the control around one
// carries the name.

export const ICONS: Record<string, string> = {
  server:
    '<rect x="2.5" y="3" width="19" height="7.5" rx="2"/><rect x="2.5" y="13.5" width="19" height="7.5" rx="2"/><circle cx="6" cy="6.75" r="0.6" fill="currentColor" stroke="none"/><circle cx="6" cy="17.25" r="0.6" fill="currentColor" stroke="none"/>',
  key:
    '<circle cx="7.5" cy="16" r="3.6"/><path d="M10.3 13.4 20 3.7"/><path d="M17 6.7l2.3 2.3"/><path d="M14.2 9.5l2 2"/>',
  lock:
    '<rect x="4.5" y="11" width="15" height="9.5" rx="2.2"/><path d="M8 11V7.3a4 4 0 0 1 8 0V11"/>',
  unlock:
    '<rect x="4.5" y="11" width="15" height="9.5" rx="2.2"/><path d="M8 11V7.3a4 4 0 0 1 7.4-2"/>',
  database:
    '<ellipse cx="12" cy="5.5" rx="7.5" ry="2.8"/><path d="M4.5 5.5v6c0 1.6 3.4 2.8 7.5 2.8s7.5-1.2 7.5-2.8v-6"/><path d="M4.5 11.5v6c0 1.6 3.4 2.8 7.5 2.8s7.5-1.2 7.5-2.8v-6"/>',
  shieldcheck:
    '<path d="M12 3l7.5 2.8v5.7c0 4.3-3.2 7.5-7.5 8.7-4.3-1.2-7.5-4.4-7.5-8.7V5.8z"/><polyline points="9 12 11 14 15.5 9.5"/>',
  shield: '<path d="M12 3l7.5 2.8v5.7c0 4.3-3.2 7.5-7.5 8.7-4.3-1.2-7.5-4.4-7.5-8.7V5.8z"/>',
  activity: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
  layers:
    '<polygon points="12 2.5 21 7 12 11.5 3 7 12 2.5"/><polyline points="3 12 12 16.5 21 12"/><polyline points="3 17 12 21.5 21 17"/>',
  zap: '<polygon points="13 2.5 4 13.5 11 13.5 10 21.5 20 10.5 13 10.5 13 2.5"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.6-6.3"/><polyline points="21 4 21 9 16 9"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><polyline points="12 7 12 12 15.5 14"/>',
  link:
    '<path d="M9.5 14.5 14.5 9.5"/><path d="M8 12 6 14a3.5 3.5 0 0 0 5 5l2-2"/><path d="M16 12l2-2a3.5 3.5 0 0 0-5-5l-2 2"/>',
  fingerprint:
    '<path d="M12 4.5a6.5 6.5 0 0 0-6.5 6.5v2"/><path d="M12 4.5a6.5 6.5 0 0 1 6.5 6.5v4"/><path d="M9 11a3 3 0 0 1 6 0v4a2 2 0 0 1-2 2"/><path d="M12 11v5"/><path d="M5.8 17.5A6.5 6.5 0 0 0 7 19"/>',
  tag:
    '<path d="M11 3.5H5a1.5 1.5 0 0 0-1.5 1.5v6a2 2 0 0 0 .6 1.4l7 7a1.6 1.6 0 0 0 2.3 0l5.7-5.7a1.6 1.6 0 0 0 0-2.3l-7-7A2 2 0 0 0 11 3.5z"/><circle cx="7.5" cy="7.5" r="1.1" fill="currentColor" stroke="none"/>',
  sliders:
    '<line x1="21" y1="5" x2="14" y2="5"/><line x1="10" y1="5" x2="3" y2="5"/><line x1="21" y1="12" x2="12" y2="12"/><line x1="8" y1="12" x2="3" y2="12"/><line x1="21" y1="19" x2="16" y2="19"/><line x1="12" y1="19" x2="3" y2="19"/><line x1="14" y1="3" x2="14" y2="7"/><line x1="8" y1="10" x2="8" y2="14"/><line x1="16" y1="17" x2="16" y2="21"/>',
  grid:
    '<rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/>',
  copy:
    '<rect x="9" y="9" width="11.5" height="11.5" rx="2.2"/><path d="M5.5 15H5a1.5 1.5 0 0 1-1.5-1.5V5A1.5 1.5 0 0 1 5 3.5h8.5A1.5 1.5 0 0 1 15 5v.5"/>',
  check: '<polyline points="20 6 9 17 4 12"/>',
  moon: '<path d="M20.5 13A8.5 8.5 0 1 1 11 3.5 6.6 6.6 0 0 0 20.5 13z"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M19.1 4.9l-1.8 1.8M6.7 17.3l-1.8 1.8"/>',
  alert:
    '<path d="M10.3 3.8 1.8 18a1.9 1.9 0 0 0 1.7 2.9h17a1.9 1.9 0 0 0 1.7-2.9L13.7 3.8a1.9 1.9 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13.5"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  enter: '<polyline points="9 10 4 14 9 18"/><path d="M4 14h11a5 5 0 0 0 5-5V6"/>',
  trash:
    '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M5 20.5a7 7 0 0 1 14 0"/>',
  plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
  download: '<path d="M12 3.5v11"/><polyline points="7.5 10.5 12 15 16.5 10.5"/><path d="M5 20.5h14"/>',
  chevronDown: '<polyline points="6 9 12 15 18 9"/>',
  chevronRight: '<polyline points="9 6 15 12 9 18"/>',
  searchIcon: '<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.8" y2="16.8"/>',
  file: '<path d="M14 3.5H7A2 2 0 0 0 5 5.5v13A2 2 0 0 0 7 20.5h10a2 2 0 0 0 2-2V8.5z"/><polyline points="14 3.5 14 8.5 19 8.5"/>',
  box: '<polygon points="12 2.5 21 7 12 11.5 3 7 12 2.5"/><polyline points="3 12 12 16.5 21 12"/><polyline points="3 17 12 21.5 21 17"/>',
  x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
  close: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
  more: '<circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>',
  chevronLeft: '<path d="m15 18-6-6 6-6"/>',
  chevronUp: '<path d="m18 15-6-6-6 6"/>',
  menu: '<line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="20" y2="18"/>',
  panelLeft: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18"/>',
  monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
  externalLink: '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
  terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
};

export type IconName = keyof typeof ICONS;

export function Icon({
  name,
  size = 16,
  stroke = 1.7,
  color = "currentColor",
  style,
}: {
  name: IconName | string;
  size?: number;
  stroke?: number;
  color?: string;
  style?: React.CSSProperties;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={stroke}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      style={{ flexShrink: 0, display: "block", ...style }}
      dangerouslySetInnerHTML={{ __html: ICONS[name] || "" }}
    />
  );
}
