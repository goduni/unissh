// Donation addresses and support links, in one place.
//
// These are published on three independent surfaces — the Support tab, README.md and
// unissh.dev/support — precisely so a reader can compare two before sending anything:
// clipboard-replacing malware is the realistic attack, and one surface being edited
// without the others would destroy the only defence a user has. wallets.test.ts fails
// if the README or the website page drifts from this list.
//
// Labels are the network names people look for in their wallet, not token names. ERC20
// and BEP20 are separate rows even though one EVM key backs both: someone scanning for
// their chain should find it, not be expected to know the two share an address format.

export interface Wallet {
  /** Network label, exactly as published. */
  label: string;
  address: string;
}

export const WALLETS: readonly Wallet[] = [
  { label: "BTC", address: "bc1qc683mf2rh63ng4eegv0emzejrhy6uux5k0zg2y" },
  { label: "BEP20", address: "0x63E3e9E690f64f149A4F920396E47328cACa6aA7" },
  { label: "ERC20", address: "0x63E3e9E690f64f149A4F920396E47328cACa6aA7" },
  { label: "TRC20", address: "TSzgPmq6LQXijuistHFFCdeTZsYZXPSfEJ" },
  { label: "TON", address: "UQCA3uYaDrMTc7cPR_DUxvqCZeAgg-2skRCLOpNrKfdg7_3d" },
  { label: "SOL", address: "jSsCcdS8Vaw1qvzUSioQ63r4niw9h914WqwmsfFA7eM" },
] as const;

/** Contact for anything the wallets above don't cover. Also the security-report address
 *  (SECURITY.md), which is why the Support tab states plainly that it is not a support
 *  desk — bug reports belong in Issues. */
export const CONTACT_EMAIL = "uni@goduni.me";

export const LINKS = {
  repo: "https://github.com/goduni/unissh",
  newIssue: "https://github.com/goduni/unissh/issues/new/choose",
  telegram: "https://t.me/unissh",
  contributing: "https://github.com/goduni/unissh/blob/main/CONTRIBUTING.md",
  supportPage: "https://unissh.dev/support",
} as const;
