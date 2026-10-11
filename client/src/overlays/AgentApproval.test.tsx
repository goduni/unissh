import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import "@/i18n";
import { ThemeProvider } from "@/theme/ThemeProvider";
import { ApprovalDialog, ARM_DELAY_MS, takesAnswer, type ApprovalRequest } from "./AgentApproval";

const request: ApprovalRequest = {
  id: 7,
  origin: "system",
  host: "",
  key: "work",
  vault: "Personal",
  pid: 4242,
  executable: "/usr/bin/ssh",
  user: "deploy",
  waiting: 0,
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

  // No DOM here, so the rule itself: the buttons, Enter and Space on them,
  // Escape and the backdrop all answer through it.
  it("ignores every answer until it has been up for the arming delay, and while one is being sent", () => {
    const shownAt = 1_000;
    expect(takesAnswer(null, shownAt, false)).toBe(false);
    expect(takesAnswer(shownAt, shownAt + ARM_DELAY_MS - 1, false)).toBe(false);
    expect(takesAnswer(shownAt, shownAt + ARM_DELAY_MS, false)).toBe(true);
    expect(takesAnswer(shownAt, shownAt + ARM_DELAY_MS, true)).toBe(false);
  });

  it("says how many more requests are waiting behind the one on screen", () => {
    const markup = renderToStaticMarkup(
      <ThemeProvider>
        <ApprovalDialog req={{ ...request, waiting: 3 }} onDone={() => {}} />
      </ThemeProvider>,
    );
    expect(markup).toContain("3 more requests are waiting");
  });
});
