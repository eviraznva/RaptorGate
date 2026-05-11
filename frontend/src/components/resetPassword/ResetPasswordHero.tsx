export function ResetPasswordHero() {
  return (
    <section className="border-b border-[#262626] px-6 py-8 sm:px-10 lg:px-12">
      <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
        <div>
          <div className="mb-4 flex items-center gap-3">
            <span className="inline-flex h-2 w-2 rounded-full bg-[#06b6d4] shadow-[0_0_14px_rgba(6,182,212,0.8)]" />
            <span className="text-[11px] uppercase tracking-[0.28em] text-[#8a8a8a]">
              Credential Recovery
            </span>
          </div>

          <h1 className="text-3xl font-light tracking-[0.24em] text-[#f5f5f5] sm:text-4xl">
            RAPTORGATE
          </h1>

          <p className="mt-4 max-w-2xl text-sm leading-7 text-[#8a8a8a]">
            Panel resetowania hasła utrzymany w aktualnej estetyce projektu:
            techniczny, surowy, ciemny i precyzyjny. Wyraźne podziały,
            turkusowy akcent i konsolowy charakter interfejsu bezpieczeństwa.
          </p>
        </div>

        <div className="border border-[#262626] bg-[#0c0c0c] px-5 py-5">
          <div className="text-[11px] uppercase tracking-[0.24em] text-[#4a4a4a]">
            Security note
          </div>

          <p className="mt-3 text-sm leading-7 text-[#8a8a8a]">
            Do resetu wymagane są: nazwa użytkownika, recovery token i nowe
            hasło. Ten ekran jest celowo oszczędny i techniczny, żeby wizualnie
            pasował do reszty panelu.
          </p>

          <div className="mt-5 h-px bg-gradient-to-r from-[#f43f5e]/0 via-[#f43f5e]/55 to-[#f43f5e]/0" />

          <p className="mt-4 text-[11px] uppercase tracking-[0.24em] text-[#f43f5e]">
            Restricted recovery flow
          </p>
        </div>
      </div>
    </section>
  );
}