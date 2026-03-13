export class IpsSignatureCategoryIsInvalidException extends Error {
  constructor(category: string) {
    super(
      `The IPS signature category "${category}" is invalid. Allowed values are: sqli, xss, shellcode, path-traversal, rce, lfi, rfi, other.`,
    );

    this.name = 'IpsSignatureCategoryIsInvalidException';
  }
}
