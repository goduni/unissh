import { invoke } from "@tauri-apps/api/core";

export type McpApprovalMode = "manual" | "trusted";

export interface McpTarget { vault_id: string; profile_id: string; label: string; host: string; port: number; user: string }
export interface McpSelection { targets: McpTarget[]; vaults: { id: string; name: string }[]; ticket: string }
export interface McpIntegration { id: string; label: string }
export interface McpSession { target?: McpTarget; expires_at: number | null; idle_seconds: number; session_id: string; target_id: string; state: string; integration_id: string; error: string | null }
export interface McpRun { session_id: string | null; run_id: string; state: string; integration_id: string; error: string | null; command?: string; cwd?: string | null; target?: McpTarget; timeout_ms?: number; approval_remaining_seconds?: number }
export interface McpStatus {
  enabled: boolean; port: number; endpoint: string; error: string | null; integrations: McpIntegration[];
  activity: { grants: { integration_id: string; remaining_seconds: number | null; approval_mode: McpApprovalMode; targets: McpTarget[] }[]; sessions: McpSession[]; runs: McpRun[] };
}
export const mcpStatus = () => invoke<McpStatus>("mcp_status");
export const mcpEnable = (enabled: boolean, port: number) => invoke<void>("mcp_set_enabled", { enabled, port });
export const mcpCreate = (label: string) => invoke<{ id: string; token: string }>("mcp_create_integration", { label });
export const mcpRotate = (id: string) => invoke<{ id: string; token: string }>("mcp_rotate_integration", { id });
export const mcpDelete = (id: string) => invoke<void>("mcp_delete_integration", { id });
export const mcpTargets = () => invoke<McpSelection>("mcp_targets");
export const mcpGrant = (id: string, targets: McpTarget[], seconds: number | null, ticket: string, approvalMode: McpApprovalMode) => invoke<void>("mcp_grant", { id, targets: targets.map(({ vault_id, profile_id }) => ({ vault_id, profile_id })), seconds, ticket, approvalMode });
export const mcpRevoke = (id: string | null = null) => invoke<void>("mcp_revoke", { id });
export const mcpApprove = (runId: string, allowed: boolean) => invoke<void>("mcp_approve", { runId, allowed });
export const mcpCloseSession = (sessionId: string) => invoke<void>("mcp_close_session", { sessionId });
export const mcpCancelCommand = (runId: string) => invoke<void>("mcp_cancel_command", { runId });

/** JSON notation makes control characters and literal backslashes unambiguous. */
export function visibleCommand(command: string): string {
  return JSON.stringify(command).replace(/[\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
/** Deliberately excludes the secret, even directly after token creation. */
export function mcpConfiguration(endpoint: string): string {
  return JSON.stringify({ mcpServers: { UniSSH: { type: "http", url: endpoint, headers: { Authorization: "Bearer <TOKEN>" } } } }, null, 2);
}
