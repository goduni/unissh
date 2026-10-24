import type { RefObject } from "react";
import { useTranslation } from "react-i18next";
import { AccountMenu } from "./AccountMenu";
import { Icon } from "../ui/icons";
import { Wordmark } from "./Mark";

/**
 * The header of the shell: 48 px, the ground at 95 % with a blur and a rule under it. At the left the name of the
 * section from 768 px up; below it the drawer's button and the wordmark. At the right the state of the keyset (said in
 * a word, from 640 px up; the account menu says it on a phone) and the account.
 */
export function Header({
  section,
  drawerOpen,
  onOpenDrawer,
  drawerButtonRef,
}: {
  section: string;
  drawerOpen: boolean;
  onOpenDrawer: () => void;
  drawerButtonRef: RefObject<HTMLButtonElement | null>;
}) {
  const { t } = useTranslation();
  return (
    <header className="sh-header">
      <button
        ref={drawerButtonRef}
        type="button"
        className="sh-icon-btn sh-focus sh-only-phone"
        aria-label={t("nav.openMenu")}
        aria-haspopup="dialog"
        aria-expanded={drawerOpen}
        onClick={onOpenDrawer}
      >
        <Icon name="menu" size={20} />
      </button>
      <span className="sh-only-phone" style={{ display: "flex", minWidth: 0 }}>
        <Wordmark />
      </span>
      <span className="sh-section sh-only-wide">{section}</span>
      <div className="sh-header-end">
        <span className="sh-badge sh-badge-wide">
          <span aria-hidden="true" className="sh-badge-dot" />
          {t("access.keysetUnlocked")}
        </span>
        <AccountMenu />
      </div>
    </header>
  );
}
