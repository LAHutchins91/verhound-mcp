import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { parseManifest } from "../src/manifest/parse.js";
import { advisoryFromOsv } from "../src/advisories.js";

describe("manifest parsers", () => {
  it("reads package.json pins and ranges", () => {
    const parsed = parseManifest("package.json", JSON.stringify({
      dependencies: { express: "4.17.1", leftpad: "^1.0.0", __proto__: "1.0.0" },
      engines: { node: ">=18" }
    }));
    expect(parsed.dependencies.map((dep) => dep.name)).toEqual(["express", "leftpad"]);
    expect(parsed.dependencies.find((dep) => dep.name === "express")?.version).toBe("4.17.1");
    expect(parsed.unresolved.some((item) => item.reason.includes("range, not a pinned version"))).toBe(true);
    expect(parsed.runtimes[0]?.product).toBe("nodejs");
  });

  it("reads npm lockfiles v1 and v2", () => {
    const v2 = parseManifest("package-lock.json", JSON.stringify({
      lockfileVersion: 2,
      packages: { "": {}, "node_modules/express": { version: "4.17.1" }, "node_modules/devdep": { version: "1.0.0", dev: true } }
    }));
    expect(v2.dependencies.map((dep) => dep.name)).toEqual(["express"]);
    const v1 = parseManifest("package-lock.json", JSON.stringify({
      dependencies: { express: { version: "4.17.1", dependencies: { qs: { version: "6.7.0" } } } }
    }));
    expect(v1.format).toContain("v1");
    expect(v1.dependencies.map((dep) => dep.name).sort()).toEqual(["express", "qs"]);
  });

  it("reads requirements markers, poetry, pep 621, and go.mod replace", () => {
    const req = parseManifest("requirements.txt", "requests[security]==2.31.0 ; python_version >= '3.8' \\\r\n  --hash=sha256:abc\r\n");
    expect(req.dependencies[0]).toMatchObject({ name: "requests", version: "2.31.0" });
    const poetry = parseManifest("pyproject.toml", "[project]\nrequires-python = \">=3.11\"\ndependencies = [\"requests==2.31.0\"]\n[tool.poetry.dependencies]\npython = \"^3.11\"\nhttpx = \"0.27.0\"\n");
    expect(poetry.dependencies.map((dep) => dep.name)).toContain("requests");
    expect(poetry.runtimes.some((runtime) => runtime.product === "python")).toBe(true);
    const lock = parseManifest("poetry.lock", "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n");
    expect(lock.dependencies[0]?.version).toBe("2.31.0");
    const go = parseManifest("go.mod", "module example.com/app\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.1\n\nreplace github.com/gin-gonic/gin => ./local\n");
    expect(go.unresolved[0]?.reason).toContain("local path");
    expect(parseManifest("pnpm-lock.yaml", "lockfileVersion: 9").notes.join(" ")).toContain("not parsed");
    expect(parseManifest("yarn.lock", "").notes.join(" ")).toContain("not parsed");
  });

  it("does not throw on hostile input", () => {
    fc.assert(fc.property(fc.string({ maxLength: 4000 }), (content) => {
      for (const name of ["package.json", "package-lock.json", "requirements.txt", "pyproject.toml", "poetry.lock", "go.mod", "pnpm-lock.yaml"]) {
        const parsed = parseManifest(name, content);
        expect(parsed.dependencies.length).toBeLessThan(5000);
      }
      return true;
    }), { numRuns: 40 });
  });
});

describe("advisory severity level", () => {
  it("uses the database level, not the CVSS vector, for the level", () => {
    const advisory = advisoryFromOsv({
      id: "GHSA-aaaa-bbbb-cccc",
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      database_specific: { severity: "MODERATE" }
    });
    expect(advisory?.severity?.score).toContain("CVSS:3.1");
    expect(advisory?.severity?.level).toBe("moderate");
  });
});
