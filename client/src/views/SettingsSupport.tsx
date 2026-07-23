// Settings → Support.
//
// The entire nagging surface of this feature is this tab. There is no badge, no toast,
// no first-run prompt and no banner anywhere else in the app: the tab is a place you can
// go, never a thing that arrives.
//
// The free ways to help are listed ABOVE the wallets on purpose. That ordering is the
// difference between a project that accepts support and one that asks for it.

import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Btn, Icon } from "@/components/primitives";
import { useTranslation } from "@/i18n";
import { guard } from "@/store/action";
import { useApp } from "@/store/app";
import { toast } from "@/store/toast";
import { CONTACT_EMAIL, LINKS, WALLETS } from "@/support/wallets";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO } from "@/theme/tokens";
import { SectionLabel } from "./ViewSettings";

/** One "costs nothing" row: a labelled action that opens a URL, with copy alongside
 *  because the machine running UniSSH is often not the machine you browse from. */
function HelpRow({ title, desc, url }: { title: string; desc: string; url: string }) {
  const p = usePalette();
  const { t } = useTranslation();
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "10px 0",
        borderBottom: `1px solid ${p.line}`,
      }}
    >
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, color: p.txt }}>{title}</div>
        <div style={{ fontSize: 12, color: p.txt3 }}>{desc}</div>
      </div>
      <Btn
        variant="ghost"
        size="sm"
        icon="ar"
        onClick={() => void guard(async () => openUrl(url))}
        title={t("support.open")}
        aria-label={`${t("support.open")}: ${title}`}
      />
      <Btn
        variant="ghost"
        size="sm"
        icon="copy"
        onClick={() =>
          void guard(async () => {
            await writeText(url);
            toast(t("settings.linkCopied"), "ok");
          })
        }
        title={t("settings.copyLink")}
        aria-label={`${t("settings.copyLink")}: ${title}`}
      />
    </div>
  );
}

/** One wallet. Copy and QR are the only actions — there is nothing here to open. */
function WalletRow({ label, address }: { label: string; address: string }) {
  const p = usePalette();
  const { t } = useTranslation();
  const openModal = useApp((s) => s.openModal);
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "10px 0",
        borderBottom: `1px solid ${p.line}`,
      }}
    >
      <span
        style={{
          flex: "0 0 62px",
          fontFamily: MONO,
          fontSize: 12,
          fontWeight: 700,
          color: p.txt2,
        }}
      >
        {label}
      </span>
      <span
        className="uh-selectable"
        title={address}
        style={{
          flex: 1,
          minWidth: 0,
          fontFamily: MONO,
          fontSize: 12,
          color: p.txt,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {address}
      </span>
      <Btn
        variant="ghost"
        size="sm"
        icon="grid"
        onClick={() => openModal({ kind: "qr", label, address })}
        title={t("support.showQr")}
        aria-label={`${t("support.showQr")}: ${label}`}
      />
      <Btn
        variant="ghost"
        size="sm"
        icon="copy"
        onClick={() =>
          void guard(async () => {
            await writeText(address);
            toast(t("support.addressCopied"), "ok");
          })
        }
        title={t("settings.copyLink")}
        aria-label={`${t("support.addressCopied")}: ${label}`}
      />
    </div>
  );
}

export function SettingsSupport() {
  const p = usePalette();
  const { t } = useTranslation();

  return (
    <>
      <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 16 }}>
        <span
          style={{
            width: 44,
            height: 44,
            borderRadius: 14,
            background: p.bg2,
            border: `1px solid ${p.line}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon name="heart" size={20} color={p.txt2} stroke={1.8} />
        </span>
        <p style={{ margin: 0, fontSize: 13, lineHeight: 1.6, color: p.txt2, maxWidth: "58ch" }}>
          {t("support.lede")}
        </p>
      </div>

      <SectionLabel first>{t("support.freeLabel")}</SectionLabel>
      <HelpRow title={t("support.star")} desc={t("support.starDesc")} url={LINKS.repo} />
      <HelpRow title={t("support.bug")} desc={t("support.bugDesc")} url={LINKS.newIssue} />
      <HelpRow title={t("support.chat")} desc={t("support.chatDesc")} url={LINKS.telegram} />
      <HelpRow
        title={t("support.translate")}
        desc={t("support.translateDesc")}
        url={LINKS.contributing}
      />

      <SectionLabel>{t("support.whyLabel")}</SectionLabel>
      <p
        style={{ margin: "0 0 6px", fontSize: 13, lineHeight: 1.6, color: p.txt2, maxWidth: "58ch" }}
      >
        {t("support.why")}
      </p>

      <SectionLabel>{t("support.donateLabel")}</SectionLabel>
      {WALLETS.map((w) => (
        <WalletRow key={w.label} label={w.label} address={w.address} />
      ))}
      <p
        style={{
          margin: "14px 0 0",
          fontSize: 12,
          lineHeight: 1.55,
          color: p.txt3,
          maxWidth: "62ch",
        }}
      >
        {t("support.verify")}
      </p>

      <SectionLabel>{t("support.contactLabel")}</SectionLabel>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "10px 0",
          borderBottom: `1px solid ${p.line}`,
        }}
      >
        <span
          className="uh-selectable"
          style={{ flex: 1, minWidth: 0, fontFamily: MONO, fontSize: 13, color: p.txt }}
        >
          {CONTACT_EMAIL}
        </span>
        <Btn
          variant="ghost"
          size="sm"
          icon="copy"
          onClick={() =>
            void guard(async () => {
              await writeText(CONTACT_EMAIL);
              toast(t("settings.linkCopied"), "ok");
            })
          }
          title={t("settings.copyLink")}
          aria-label={t("settings.copyLink")}
        />
      </div>
      <p
        style={{
          margin: "10px 0 0",
          fontSize: 12,
          lineHeight: 1.55,
          color: p.txt3,
          maxWidth: "58ch",
        }}
      >
        {t("support.contactDesc")}
      </p>
    </>
  );
}
