type DnsValidationErrorsProps = {
  errors: string[];
};

export default function DnsValidationErrors({ errors }: DnsValidationErrorsProps) {
  if (errors.length === 0) {
    return null;
  }

  return (
    <div className="bg-[#161616] border border-[#f43f5e]/50 p-4 mb-6">
      <div className="text-sm text-[#f43f5e] mb-2">Validation errors</div>
      <ul className="text-xs text-[#fca5a5] space-y-1">
        {errors.map((error) => (
          <li key={error}>- {error}</li>
        ))}
      </ul>
    </div>
  );
}
