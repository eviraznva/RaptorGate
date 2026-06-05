const domainPattern =
  /^(?=.{1,253}$)(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

export function normalizeBypassDomainInput(domain: string): string {
  return domain.trim().toLowerCase();
}

export function validateBypassDomainInput(domain: string): string[] {
  const errors: string[] = [];
  const normalized = normalizeBypassDomainInput(domain);

  if (normalized.length === 0) {
    errors.push("Domain is required.");
    return errors;
  }

  if (!domainPattern.test(normalized)) {
    errors.push("Domain must be a valid FQDN or wildcard domain.");
  }

  return errors;
}
