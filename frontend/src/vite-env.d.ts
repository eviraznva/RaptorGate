interface ViteTypeOptions {
  // By adding this line, you can make the type of ImportMetaEnv strict
  // to disallow unknown keys.
  // strictImportMetaEnv: unknown
}

interface ImportMetaEnv {
  readonly RAPTOR_GATE_APP_TITLE: string;
  readonly RAPTOR_GATE_API_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
