import { beforeEach, expect, it } from "vitest";
import { clearAuthPrompts, dismissAuthPrompt, enqueueAuthPrompt, useAuthPrompts, type AuthPromptRequest } from "./authPrompt";
const prompt = (id: number): AuthPromptRequest => ({ id, host: "test", port: 22, user: "test", name: "OTP", instruction: "", prompts: [{ prompt: "Code", echo: false }] });
beforeEach(clearAuthPrompts);
it("keeps the next prompt when an older invocation finishes after native cancellation", () => {
  enqueueAuthPrompt(prompt(1)); enqueueAuthPrompt(prompt(2));
  dismissAuthPrompt(1); // Native cancellation advances to the second prompt.
  dismissAuthPrompt(1); // Delayed completion of the first invoke must not advance again.
  expect(useAuthPrompts.getState().requests.map(r => r.id)).toEqual([2]);
  dismissAuthPrompt(2); expect(useAuthPrompts.getState().requests).toEqual([]);
});
it("cancels queued prompts independently and clears priority on teardown", () => {
  enqueueAuthPrompt(prompt(1)); enqueueAuthPrompt(prompt(2)); enqueueAuthPrompt(prompt(3));
  dismissAuthPrompt(2);
  expect(useAuthPrompts.getState().requests.map(r => r.id)).toEqual([1, 3]);
  clearAuthPrompts(); dismissAuthPrompt(1);
  expect(useAuthPrompts.getState().requests).toEqual([]);
});
