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
    const pnpm = parseManifest("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    devDependencies:\n      vitest:\n        version: 2.0.0\n\npackages:\n  express@4.18.2:\n    resolution: {integrity: sha512-abc}\n  vitest@2.0.0:\n    resolution: {integrity: sha512-def}\n");
    expect(pnpm.dependencies.map((dep) => dep.name)).toEqual(["express"]);
    const yarn = parseManifest("yarn.lock", "express@^4.17.1:\n  version \"4.17.1\"\n  resolved \"https://registry.yarnpkg.com/express/-/express-4.17.1.tgz\"\n");
    expect(yarn.dependencies[0]).toMatchObject({ name: "express", version: "4.17.1", ecosystem: "npm" });
  });

  it("reads cargo, maven, nuget, ruby, and composer lockfiles", () => {
    const cargo = parseManifest("Cargo.lock", "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n");
    expect(cargo.dependencies[0]).toMatchObject({ ecosystem: "cargo", name: "serde", version: "1.0.210" });
    const pom = parseManifest("pom.xml", "<project><dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.16</version></dependency></dependencies><build><plugins><plugin><dependencies><dependency><groupId>com.example</groupId><artifactId>plugin-dep</artifactId><version>1.0.0</version></dependency></dependencies></plugin></plugins></build></project>");
    expect(pom.dependencies.map((dep) => dep.name)).toEqual(["org.slf4j:slf4j-api"]);
    const csproj = parseManifest("App.csproj", "<Project><ItemGroup><PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.3\" /></ItemGroup></Project>");
    expect(csproj.dependencies[0]).toMatchObject({ ecosystem: "nuget", name: "Newtonsoft.Json", version: "13.0.3" });
    const nugetLock = parseManifest("packages.lock.json", JSON.stringify({ dependencies: { "net8.0": { "Newtonsoft.Json": { type: "Direct", resolved: "13.0.3" } } } }));
    expect(nugetLock.dependencies[0]?.version).toBe("13.0.3");
    const gems = parseManifest("Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.8)\n\nPLATFORMS\n  ruby\n");
    expect(gems.dependencies[0]).toMatchObject({ ecosystem: "rubygems", name: "rack", version: "3.1.8" });
    const composer = parseManifest("composer.lock", JSON.stringify({ packages: [{ name: "monolog/monolog", version: "v3.7.0", version_normalized: "3.7.0.0" }] }));
    expect(composer.dependencies[0]).toMatchObject({ ecosystem: "composer", name: "monolog/monolog", version: "3.7.0" });
  });

  it("does not throw on hostile input", () => {
    fc.assert(fc.property(fc.string({ maxLength: 4000 }), (content) => {
      for (const name of ["package.json", "package-lock.json", "requirements.txt", "pyproject.toml", "poetry.lock", "go.mod", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "pom.xml", "App.csproj", "packages.lock.json", "Gemfile.lock", "composer.lock"]) {
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
