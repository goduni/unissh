import { beforeEach, expect, it, vi } from "vitest";
import { recoverInstance } from "./recovery";

const mocks = vi.hoisted(() => ({ recover: vi.fn(), create: vi.fn(), clear: vi.fn(), boot: vi.fn() }));
vi.mock("@/bridge/api", () => ({ serverEscrowFetchAndUnlock: mocks.recover, createAccount: mocks.create }));
vi.mock("@/bridge/secretKey", () => ({ clearSecretKey: mocks.clear }));
vi.mock("./app", () => ({ useApp: { getState: () => ({ boot: mocks.boot }) } }));
beforeEach(() => vi.resetAllMocks());

it("recovers before boot without creating another identity or changing the password", async () => {
  await recoverInstance(" https://sync.example.com ", " alice ", " pass word ", "AA-BB CC");
  expect(mocks.create).not.toHaveBeenCalled();
  expect(mocks.recover).toHaveBeenCalledWith("https://sync.example.com", "alice", " pass word ", "AABBCC");
  expect(mocks.boot).toHaveBeenCalledOnce();
  expect(mocks.clear.mock.invocationCallOrder[0]).toBeLessThan(mocks.boot.mock.invocationCallOrder[0]);
});

it("supports passwordless identities", async () => {
  await recoverInstance("https://sync.example.com", "alice", "", "ab".repeat(32));
  expect(mocks.recover).toHaveBeenCalledWith("https://sync.example.com", "alice", null, "ab".repeat(32));
});

it("preserves the recovery form on failure and invalidates stale keychain cache", async () => {
  const error = new Error("enrollment unavailable");
  mocks.recover.mockRejectedValue(error);
  await expect(recoverInstance("https://sync.example.com", "alice", "pw", "ab".repeat(32))).rejects.toBe(error);
  expect(mocks.create).not.toHaveBeenCalled();
  expect(mocks.boot).not.toHaveBeenCalled();
  expect(mocks.clear).toHaveBeenCalledOnce();
});
