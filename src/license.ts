export interface LicensePolicy {
  allow?: string[];
  deny?: string[];
}

export interface LicenseAssessment {
  flags: string[];
  reasons: string[];
}

function tokens(license: string): string[] {
  return license.split(/\s+(?:OR|AND|WITH)\s+|[()/]/i).map((part) => part.trim()).filter(Boolean);
}

function norm(value: string): string {
  return value.trim().toLowerCase();
}

/** Strong copyleft: GPL, AGPL, and SSPL. LGPL is not included. */
export function isStrongCopyleft(license: string): boolean {
  const value = license.toUpperCase();
  if (value.includes("LGPL") || value.includes("LESSER")) return false;
  if (value.includes("AGPL") || value.includes("AFFERO")) return true;
  if (value.includes("SSPL") || value.includes("SERVER SIDE PUBLIC LICENSE")) return true;
  if (value.includes("GPL") || value.includes("GNU GENERAL PUBLIC LICENSE")) return true;
  return false;
}

export function assessLicenses(licenses: string[], policy: LicensePolicy | undefined, exists: boolean): LicenseAssessment {
  const flags: string[] = [];
  const reasons: string[] = [];
  if (!exists) return { flags, reasons };
  const declared = licenses.map((item) => item.trim()).filter(Boolean);
  if (!declared.length) {
    flags.push("no_license");
    reasons.push("No license is declared in package metadata.");
  }
  if (declared.some((license) => isStrongCopyleft(license) || tokens(license).some((token) => isStrongCopyleft(token)))) {
    flags.push("strong_copyleft");
    reasons.push("Declared license is strong copyleft (GPL, AGPL, or SSPL).");
  }
  const deny = (policy?.deny ?? []).map(norm).filter(Boolean);
  const allow = (policy?.allow ?? []).map(norm).filter(Boolean);
  const parts = declared.flatMap((license) => [norm(license), ...tokens(license).map(norm)]);
  if (deny.length && parts.some((part) => deny.includes(part))) {
    flags.push("license_denied");
    reasons.push("Declared license is on the deny list.");
  }
  if (allow.length && declared.length && !declared.every((license) => {
    const piece = [norm(license), ...tokens(license).map(norm)];
    return piece.some((part) => allow.includes(part));
  })) {
    flags.push("license_not_allowed");
    reasons.push("Declared license is not on the allow list.");
  }
  return { flags, reasons };
}
