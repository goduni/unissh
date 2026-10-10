import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import "@/i18n";
import { ThemeProvider } from "@/theme/ThemeProvider";
import { ApprovalDialog, type ApprovalRequest } from "./AgentApproval";

const request: ApprovalRequest = {
  id: 7,
  origin: "system",
  host: "",
  key: "work",
  vault: "Personal",
  pid: 4242,
  executable: "/usr/bin/ssh",
  user: "deploy",
};

describe("agent approval prompt", () => {
  // A queued prompt appears where the answered one was. Its buttons must not be
  // live on the first frame, or the second click of a double-click signs a
  // request nobody read.
  it("shows a new prompt with both answers disabled until it has been on screen", () => {
    const markup = renderToStaticMarkup(
      <ThemeProvider>
        <ApprovalDialog req={request} onDone={() => {}} />
      </ThemeProvider>,
    );
    const buttons = markup.match(/<button[^>]*>/g) ?? [];
    const answers = buttons.filter((b) => b.includes("disabled"));
    expect(answers).toHaveLength(2);
  });
});
