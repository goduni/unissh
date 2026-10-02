import { describe, expect, it } from "vitest";
import { parseParams, splitBuiltins, substituteParams } from "./snippetParams";

describe("snippet parameters", () => {
  it("finds nothing in a plain command", () => {
    expect(parseParams("systemctl restart nginx")).toEqual([]);
  });

  it("finds one parameter and substitutes it", () => {
    const cmd = "systemctl restart {{service}}";
    expect(parseParams(cmd)).toEqual([{ name: "service", default: null, position: 18 }]);
    expect(substituteParams(cmd, { service: "nginx" })).toBe("systemctl restart nginx");
  });

  it("asks a repeated name once, at its first position, and fills every occurrence", () => {
    const cmd = "echo {{x}} && echo {{x:late}}";
    expect(parseParams(cmd)).toEqual([{ name: "x", default: null, position: 5 }]);
    expect(substituteParams(cmd, { x: "1" })).toBe("echo 1 && echo 1");
  });

  it("reads a default", () => {
    expect(parseParams("journalctl -u {{unit:nginx.service}} -n 200")).toEqual([
      { name: "unit", default: "nginx.service", position: 14 },
    ]);
  });

  it("tells an empty default apart from no default", () => {
    expect(parseParams("ls {{flags:}}")).toEqual([{ name: "flags", default: "", position: 3 }]);
  });

  it("types an escaped \\{{ as a literal {{", () => {
    const cmd = "echo \\{{x}} {{y}}";
    expect(parseParams(cmd).map((p) => p.name)).toEqual(["y"]);
    expect(substituteParams(cmd, { x: "no", y: "yes" })).toBe("echo {{x}} yes");
  });

  it("leaves spaced braces as literal text", () => {
    const cmd = "echo '{{ .Status }}'";
    expect(parseParams(cmd)).toEqual([]);
    expect(substituteParams(cmd, {})).toBe(cmd);
  });

  it("pins nested-looking braces: only the inner well-formed placeholder counts", () => {
    const cmd = "{{a{{b}}}}";
    expect(parseParams(cmd)).toEqual([{ name: "b", default: null, position: 3 }]);
    expect(substituteParams(cmd, { a: "A", b: "B" })).toBe("{{aB}}");
  });

  it("lets a built-in with a value shadow a user parameter, and asks it when there is none", () => {
    const params = parseParams("ssh {{user:root}}@{{host}} -p {{port}} {{cmd}}");
    expect(splitBuiltins(params, { host: "web1", user: "deploy", port: "22" })).toEqual({
      ask: [{ name: "cmd", default: null, position: 39 }],
      fromHost: [
        { name: "user", value: "deploy" },
        { name: "host", value: "web1" },
        { name: "port", value: "22" },
      ],
    });
    expect(splitBuiltins(params, {}).ask.map((p) => p.name)).toEqual(["user", "host", "port", "cmd"]);
  });

  it("lists parameters in order of first appearance, not by name", () => {
    expect(parseParams("{{zeta}} {{alpha}} {{mid}} {{alpha}}").map((p) => p.name)).toEqual([
      "zeta",
      "alpha",
      "mid",
    ]);
  });

  it("leaves a placeholder with no value visible", () => {
    expect(substituteParams("kill {{pid:1}} {{sig}}", { sig: "-9" })).toBe("kill {{pid:1}} -9");
  });
});
