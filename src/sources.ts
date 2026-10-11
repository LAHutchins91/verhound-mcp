export interface SourceCitation {
  id: string;
  name: string;
  url: string;
  attribution: string;
}

export const SOURCE = {
  osv: {
    id: "osv",
    name: "OSV.dev",
    url: "https://osv.dev",
    attribution: "Vulnerability data from OSV.dev, which aggregates the GitHub Advisory Database, PyPA Advisory Database, Go Vulnerability Database (CC-BY 4.0) and others."
  },
  depsdev: {
    id: "depsdev",
    name: "deps.dev",
    url: "https://deps.dev",
    attribution: "Package metadata from deps.dev (Google; derived data CC-BY 4.0)."
  },
  npm: {
    id: "npm",
    name: "npm registry",
    url: "https://registry.npmjs.org",
    attribution: "Package metadata from the npm registry."
  },
  pypi: {
    id: "pypi",
    name: "PyPI",
    url: "https://pypi.org",
    attribution: "Package metadata from the Python Package Index."
  },
  eol: {
    id: "endoflife.date",
    name: "endoflife.date",
    url: "https://endoflife.date",
    attribution: "Lifecycle data: endoflife.date (MIT)."
  }
} as const satisfies Record<string, SourceCitation>;

export const DATA_SOURCES_TEXT = "Vulnerability data from OSV.dev, which aggregates the GitHub Advisory Database, PyPA Advisory Database, Go Vulnerability Database (CC-BY 4.0) and others. Package metadata from deps.dev (Google; derived data CC-BY 4.0), the npm registry, and PyPI. Lifecycle data from endoflife.date (MIT). Verhound is not affiliated with or endorsed by Google, npm, PyPI, the Python Software Foundation, OSV, or endoflife.date.";

export function mergeSources(groups: SourceCitation[][]): SourceCitation[] {
  const map = new Map<string, SourceCitation>();
  for (const group of groups) {
    for (const source of group) map.set(source.id, source);
  }
  return [...map.values()];
}
