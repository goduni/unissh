import { Login } from "./access/Login";
import { Shell } from "./shell/Shell";
import { useSession } from "./store/session";
import { ThemeProvider } from "./theme/ThemeProvider";

function Root() {
  // Two-level session: a live Bearer (server-trusted) AND an unlocked keyset
  // (crypto). Escrow/claim sign-in establishes both atomically, so the Shell shows
  // only when both hold; a reload drops the in-memory session → back to Login.
  const bearer = useSession((s) => s.bearer);
  const keysetUnlocked = useSession((s) => s.keysetUnlocked);
  return bearer && keysetUnlocked ? <Shell /> : <Login />;
}

export function App() {
  return (
    <ThemeProvider>
      <Root />
    </ThemeProvider>
  );
}
