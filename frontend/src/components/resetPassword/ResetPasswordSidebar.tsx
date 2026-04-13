const items = [
  "Minimum 8 znaków",
  "Minimum 1 wielka litera",
  "Minimum 1 cyfra",
  "Minimum 1 znak specjalny",
  "Recovery token w formacie hex",
];

export function ResetPasswordSidebar() {
  return (
    <aside className="space-y-6">
      <section className="border border-[#262626] bg-[#0c0c0c] p-6">
        <div className="text-[11px] uppercase tracking-[0.24em] text-[#4a4a4a]">
          Validation matrix
        </div>

        <h3 className="mt-3 text-lg tracking-[0.14em] text-[#f5f5f5]">
          Wymagania
        </h3>

        <div className="mt-5 space-y-3">
          {items.map((item) => (
            <div
              key={item}
              className="flex items-start gap-3 border border-[#1f1f1f] bg-[#101010] px-3 py-3"
            >
              <span className="mt-1 inline-block h-1.5 w-1.5 rounded-full bg-[#06b6d4]" />
              <span className="text-sm leading-6 text-[#8a8a8a]">{item}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="border border-[#f43f5e]/20 bg-[#f43f5e]/5 px-5 py-5">
        <div className="text-[11px] uppercase tracking-[0.24em] text-[#f43f5e]">
          Sensitive operation
        </div>
        <p className="mt-3 text-sm leading-7 text-[#8a8a8a]">
          Recovery token traktuj jak pełnoprawny sekret. Wizualnie ten blok
          domyka stronę ostrzeżeniem zgodnym z językiem całego frontendu.
        </p>
      </section>
    </aside>
  );
}