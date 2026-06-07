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

interface DecryptionFailurePolicyInput {
  failureThreshold: number;
  failureWindowSec: number;
  localExclusionTtlSec: number;
  maxEntries: number;
}

export function validateDecryptionFailurePolicy(policy: DecryptionFailurePolicyInput): string[] {
  const errors: string[] = [];

  if (!Number.isInteger(policy.failureThreshold) || policy.failureThreshold < 1 || policy.failureThreshold > 1000) {
    errors.push("Failure threshold must be in range 1..1000.");
  }

  if (!Number.isInteger(policy.failureWindowSec) || policy.failureWindowSec < 1) {
    errors.push("Failure window must be at least 1 second.");
  }

  if (!Number.isInteger(policy.localExclusionTtlSec) || policy.localExclusionTtlSec < 1) {
    errors.push("Local exclusion TTL must be at least 1 second.");
  }

  if (!Number.isInteger(policy.maxEntries) || policy.maxEntries < 1) {
    errors.push("Max entries must be at least 1.");
  }

  return errors;
}
