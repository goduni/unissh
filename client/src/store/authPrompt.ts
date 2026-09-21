import { create } from "zustand";

export interface AuthPromptRequest {
  id: number;
  host: string;
  port: number;
  user: string;
  name: string;
  instruction: string;
  prompts: { prompt: string; echo: boolean }[];
}

// Shared with lower-priority approvals so only the visible dialog owns focus.
// Answers stay in the mounted dialog, never in this queue.
export const useAuthPrompts = create<{ requests: AuthPromptRequest[] }>(() => ({ requests: [] }));

export function enqueueAuthPrompt(request: AuthPromptRequest): void {
  useAuthPrompts.setState(state => state.requests.some(r => r.id === request.id)
    ? state : { requests: [...state.requests, request] });
}

/** Both native cancellation and a late invoke completion remove only their own ID. */
export function dismissAuthPrompt(id: number): void {
  useAuthPrompts.setState(state => state.requests.some(r => r.id === id)
    ? { requests: state.requests.filter(r => r.id !== id) } : state);
}

export function clearAuthPrompts(): void {
  useAuthPrompts.setState({ requests: [] });
}
