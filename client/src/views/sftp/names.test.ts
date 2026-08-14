import { describe, it, expect } from "vitest";
import { validateEntryName } from "./names";

describe("validateEntryName", () => {
  it("accepts a plain name and trims it", () => {
    expect(validateEntryName("  notes.txt  ", [])).toEqual({ name: "notes.txt", error: null });
  });

  it("rejects an empty or whitespace-only name", () => {
    expect(validateEntryName("", []).error).toBe("empty");
    expect(validateEntryName("   ", []).error).toBe("empty");
  });

  it("rejects a name already present in the directory", () => {
    expect(validateEntryName("notes.txt", ["notes.txt"]).error).toBe("dup");
  });

  it("rejects path separators", () => {
    expect(validateEntryName("a/b", []).error).toBe("invalid");
    expect(validateEntryName("a\\b", []).error).toBe("invalid");
  });

  it("rejects the dot entries that every directory already has", () => {
    expect(validateEntryName(".", []).error).toBe("invalid");
    expect(validateEntryName("..", []).error).toBe("invalid");
  });

  it("allows a leading dot in an ordinary hidden name", () => {
    expect(validateEntryName(".bashrc", []).error).toBe(null);
  });

  it("reports duplicates before separators so the message is the specific one", () => {
    expect(validateEntryName("dup", ["dup"]).error).toBe("dup");
  });

  describe("rename mode", () => {
    it("treats the unchanged name as a no-op, not a duplicate", () => {
      expect(validateEntryName("old.txt", ["old.txt"], "old.txt").error).toBe("unchanged");
    });

    it("still rejects a collision with a different existing entry", () => {
      expect(validateEntryName("other.txt", ["old.txt", "other.txt"], "old.txt").error).toBe("dup");
    });

    it("accepts a genuinely new name", () => {
      expect(validateEntryName("new.txt", ["old.txt"], "old.txt")).toEqual({ name: "new.txt", error: null });
    });
  });
});
