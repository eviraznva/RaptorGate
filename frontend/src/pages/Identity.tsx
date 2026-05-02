import { useMemo, useState, type ReactNode } from "react";
import { Icon } from "@iconify/react";
import type { ApiFailure, ApiSuccess } from "../types/ApiResponse";
import type { IdentitySession } from "../types/identity/IdentitySession";
import type {
  AdminRole,
  AdminRoleMapping,
  AdminRoleMappingMatchType,
  IdentityAuthenticationProfile,
  IdentityConfig,
  IdentityGroupSource,
  IdentityProvider,
  IdentityProviderTestResult,
  LdapServerProfile,
  LdapTlsMode,
  RadiusServerProfile,
} from "../types/identity/IdentityConfig";
import {
  useCreateAuthenticationProfileMutation,
  useCreateLdapProfileMutation,
  useCreateRadiusProfileMutation,
  useDeleteAuthenticationProfileMutation,
  useDeleteLdapProfileMutation,
  useDeleteRadiusProfileMutation,
  useGetIdentityConfigQuery,
  useTestLdapProfileMutation,
  useTestRadiusProfileMutation,
  useUpdateAuthenticationProfileMutation,
  useUpdateIdentitySettingsMutation,
  useUpdateLdapProfileMutation,
  useUpdateRadiusProfileMutation,
  type AuthenticationProfileBody,
  type LdapProfileBody,
  type RadiusProfileBody,
} from "../services/identityConfig";
import {
  useGetIdentitySessionsQuery,
  useRevokeIdentitySessionMutation,
} from "../services/identitySessions";
import { useUpsertSecretMutation } from "../services/secrets";

type TabKey =
  | "radius"
  | "ldap"
  | "auth"
  | "portal"
  | "admin"
  | "sessions"
  | "diagnostics";

type RadiusForm = RadiusProfileBody & {
  id: string | null;
  secretValue: string;
};

type LdapForm = LdapProfileBody & {
  id: string | null;
  bindPasswordValue: string;
};

type AuthForm = AuthenticationProfileBody & {
  id: string | null;
};

type TestState = {
  radiusProfileId: string;
  radiusUsername: string;
  radiusPassword: string;
  radiusCallingStationId: string;
  ldapProfileId: string;
  ldapUsername: string;
  result: IdentityProviderTestResult | null;
};

const tabs: { key: TabKey; label: string; icon: string }[] = [
  { key: "radius", label: "RADIUS Profiles", icon: "lucide:server" },
  { key: "ldap", label: "LDAP Profiles", icon: "lucide:database" },
  { key: "auth", label: "Authentication Profiles", icon: "lucide:key-round" },
  { key: "portal", label: "Portal Settings", icon: "lucide:door-open" },
  { key: "admin", label: "Admin Login", icon: "lucide:shield-check" },
  { key: "sessions", label: "Active Sessions", icon: "lucide:users" },
  { key: "diagnostics", label: "Diagnostics", icon: "lucide:activity" },
];

const roleOptions: AdminRole[] = ["super_admin", "admin", "operator", "viewer"];
const matchTypeOptions: AdminRoleMappingMatchType[] = ["username", "ldap_group", "radius_vsa"];

export default function Identity() {
  const [activeTab, setActiveTab] = useState<TabKey>("radius");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { data: configResponse, isFetching, refetch } = useGetIdentityConfigQuery();
  const { data: sessionsResponse, isFetching: sessionsFetching } = useGetIdentitySessionsQuery(undefined, { pollingInterval: 15_000 });
  const config = (configResponse as ApiSuccess<IdentityConfig> | undefined)?.data;
  const sessions =
    (sessionsResponse as ApiSuccess<{ identitySessions: IdentitySession[] }> | undefined)?.data
      ?.identitySessions ?? [];

  const [upsertSecret] = useUpsertSecretMutation();
  const [createRadiusProfile] = useCreateRadiusProfileMutation();
  const [updateRadiusProfile] = useUpdateRadiusProfileMutation();
  const [deleteRadiusProfile] = useDeleteRadiusProfileMutation();
  const [createLdapProfile] = useCreateLdapProfileMutation();
  const [updateLdapProfile] = useUpdateLdapProfileMutation();
  const [deleteLdapProfile] = useDeleteLdapProfileMutation();
  const [createAuthenticationProfile] = useCreateAuthenticationProfileMutation();
  const [updateAuthenticationProfile] = useUpdateAuthenticationProfileMutation();
  const [deleteAuthenticationProfile] = useDeleteAuthenticationProfileMutation();
  const [updateIdentitySettings] = useUpdateIdentitySettingsMutation();
  const [testRadiusProfile] = useTestRadiusProfileMutation();
  const [testLdapProfile] = useTestLdapProfileMutation();
  const [revokeIdentitySession] = useRevokeIdentitySessionMutation();

  const [radiusForm, setRadiusForm] = useState<RadiusForm>(defaultRadiusForm());
  const [ldapForm, setLdapForm] = useState<LdapForm>(defaultLdapForm());
  const [authForm, setAuthForm] = useState<AuthForm>(defaultAuthForm());
  const [testState, setTestState] = useState<TestState>({
    radiusProfileId: "",
    radiusUsername: "",
    radiusPassword: "",
    radiusCallingStationId: "",
    ldapProfileId: "",
    ldapUsername: "",
    result: null,
  });

  const radiusProfileById = useMemo(
    () => new Map((config?.radiusServerProfiles ?? []).map((profile) => [profile.id, profile])),
    [config],
  );
  const ldapProfileById = useMemo(
    () => new Map((config?.ldapServerProfiles ?? []).map((profile) => [profile.id, profile])),
    [config],
  );

  const runAction = async (action: () => Promise<unknown>, success: string) => {
    setError(null);
    setMessage(null);
    try {
      await action();
      setMessage(success);
      await refetch();
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  const saveRadius = async () => {
    await runAction(async () => {
      await upsertSecretIfNeeded(radiusForm.sharedSecretRef, radiusForm.secretValue, upsertSecret);
      const body = radiusBody(radiusForm);
      if (radiusForm.id) {
        await updateRadiusProfile({ id: radiusForm.id, ...body }).unwrap();
      } else {
        await createRadiusProfile(body).unwrap();
      }
      setRadiusForm(defaultRadiusForm());
    }, "RADIUS profile saved");
  };

  const saveLdap = async () => {
    await runAction(async () => {
      await upsertSecretIfNeeded(ldapForm.bindPasswordRef, ldapForm.bindPasswordValue, upsertSecret);
      const body = ldapBody(ldapForm);
      if (ldapForm.id) {
        await updateLdapProfile({ id: ldapForm.id, ...body }).unwrap();
      } else {
        await createLdapProfile(body).unwrap();
      }
      setLdapForm(defaultLdapForm());
    }, "LDAP profile saved");
  };

  const saveAuthProfile = async () => {
    await runAction(async () => {
      const body = authBody(authForm);
      if (authForm.id) {
        await updateAuthenticationProfile({ id: authForm.id, ...body }).unwrap();
      } else {
        await createAuthenticationProfile(body).unwrap();
      }
      setAuthForm(defaultAuthForm());
    }, "Authentication profile saved");
  };

  const updateSettings = async (body: {
    portalAuthenticationProfileId?: string | null;
    adminAuthenticationProfileId?: string | null;
  }) => {
    await runAction(async () => {
      await updateIdentitySettings(body).unwrap();
    }, "Identity settings updated");
  };

  const runRadiusTest = async () => {
    const profileId = testState.radiusProfileId || config?.radiusServerProfiles[0]?.id || "";
    if (!profileId) return;
    await runAction(async () => {
      const response = await testRadiusProfile({
        id: profileId,
        username: testState.radiusUsername,
        password: testState.radiusPassword,
        callingStationId: testState.radiusCallingStationId || undefined,
      }).unwrap();
      setTestState((current) => ({
        ...current,
        result: (response as ApiSuccess<IdentityProviderTestResult>).data,
      }));
    }, "RADIUS test completed");
  };

  const runLdapTest = async () => {
    const profileId = testState.ldapProfileId || config?.ldapServerProfiles[0]?.id || "";
    if (!profileId) return;
    await runAction(async () => {
      const response = await testLdapProfile({
        id: profileId,
        username: testState.ldapUsername,
      }).unwrap();
      setTestState((current) => ({
        ...current,
        result: (response as ApiSuccess<IdentityProviderTestResult>).data,
      }));
    }, "LDAP test completed");
  };

  if (!config && isFetching) {
    return <IdentityShell activeTab={activeTab} onTabChange={setActiveTab}><Panel title="Identity"><StateLine icon="lucide:loader-2" text="Loading identity configuration" /></Panel></IdentityShell>;
  }

  if (!config) {
    return <IdentityShell activeTab={activeTab} onTabChange={setActiveTab}><Panel title="Identity"><StateLine icon="lucide:triangle-alert" text="Identity configuration is unavailable" /></Panel></IdentityShell>;
  }

  const radiusProfiles = config.radiusServerProfiles;
  const ldapProfiles = config.ldapServerProfiles;
  const authProfiles = config.authenticationProfiles;
  const adminAuthProfiles = authProfiles.filter(
    (profile) =>
      profile.provider !== "local" ||
      profile.id === config.settings.adminAuthenticationProfileId,
  );

  return (
    <IdentityShell activeTab={activeTab} onTabChange={setActiveTab}>
      <StatusBar
        radiusCount={radiusProfiles.length}
        ldapCount={ldapProfiles.length}
        authCount={authProfiles.length}
        sessionCount={sessions.length}
        portalProfile={profileName(config.settings.portalAuthenticationProfileId, authProfiles)}
        adminProfile={profileName(config.settings.adminAuthenticationProfileId, authProfiles)}
      />
      {(message || error) && (
        <div className={`border px-4 py-3 text-sm mb-4 ${error ? "border-[#ef4444]/50 bg-[#ef4444]/10 text-[#fecaca]" : "border-[#10b981]/50 bg-[#10b981]/10 text-[#bbf7d0]"}`}>
          {error ?? message}
        </div>
      )}

      {activeTab === "radius" && (
        <div className="grid grid-cols-1 2xl:grid-cols-[minmax(0,1fr)_420px] gap-4">
          <Panel title="RADIUS Profiles" action={<IconButton icon="lucide:plus" label="New" onClick={() => setRadiusForm(defaultRadiusForm())} />}>
            <ProfileTable
              empty="No RADIUS profiles"
              rows={radiusProfiles.map((profile) => ({
                id: profile.id,
                name: profile.name,
                status: profile.isActive ? "active" : "disabled",
                primary: `${profile.host}:${profile.port}`,
                secondary: profile.sharedSecretRef,
                meta: `${profile.timeoutMs} ms / ${profile.retries} retries`,
                onEdit: () => setRadiusForm(radiusFormFromProfile(profile)),
                onDelete: () => void runAction(() => deleteRadiusProfile(profile.id).unwrap(), "RADIUS profile deleted"),
              }))}
            />
          </Panel>
          <RadiusProfileForm form={radiusForm} onChange={setRadiusForm} onSave={saveRadius} onCancel={() => setRadiusForm(defaultRadiusForm())} />
        </div>
      )}

      {activeTab === "ldap" && (
        <div className="grid grid-cols-1 2xl:grid-cols-[minmax(0,1fr)_460px] gap-4">
          <Panel title="LDAP Profiles" action={<IconButton icon="lucide:plus" label="New" onClick={() => setLdapForm(defaultLdapForm())} />}>
            <ProfileTable
              empty="No LDAP profiles"
              rows={ldapProfiles.map((profile) => ({
                id: profile.id,
                name: profile.name,
                status: profile.isActive ? "active" : "disabled",
                primary: `${profile.host}:${profile.port} / ${profile.tlsMode}`,
                secondary: profile.bindPasswordRef,
                meta: profile.userBaseDn,
                onEdit: () => setLdapForm(ldapFormFromProfile(profile)),
                onDelete: () => void runAction(() => deleteLdapProfile(profile.id).unwrap(), "LDAP profile deleted"),
              }))}
            />
          </Panel>
          <LdapProfileForm form={ldapForm} onChange={setLdapForm} onSave={saveLdap} onCancel={() => setLdapForm(defaultLdapForm())} />
        </div>
      )}

      {activeTab === "auth" && (
        <div className="grid grid-cols-1 2xl:grid-cols-[minmax(0,1fr)_500px] gap-4">
          <Panel title="Authentication Profiles" action={<IconButton icon="lucide:plus" label="New" onClick={() => setAuthForm(defaultAuthForm())} />}>
            <ProfileTable
              empty="No authentication profiles"
              rows={authProfiles.map((profile) => ({
                id: profile.id,
                name: profile.name,
                status: profile.isActive ? "active" : "disabled",
                primary: `${profile.provider} / groups: ${profile.groupSource}`,
                secondary: `RADIUS: ${profileName(profile.radiusProfileId, radiusProfiles)} / LDAP: ${profileName(profile.ldapProfileId, ldapProfiles)}`,
                meta: `${profile.sessionTtlSeconds}s / ${profile.adminRoleMappings.length} role mappings`,
                onEdit: () => setAuthForm(authFormFromProfile(profile)),
                onDelete: () => void runAction(() => deleteAuthenticationProfile(profile.id).unwrap(), "Authentication profile deleted"),
              }))}
            />
          </Panel>
          <AuthProfileForm
            form={authForm}
            onChange={setAuthForm}
            onSave={saveAuthProfile}
            onCancel={() => setAuthForm(defaultAuthForm())}
            radiusProfiles={radiusProfiles}
            ldapProfiles={ldapProfiles}
          />
        </div>
      )}

      {activeTab === "portal" && (
        <SettingsPanel
          key={config.settings.portalAuthenticationProfileId ?? "portal-disabled"}
          title="Portal Settings"
          value={config.settings.portalAuthenticationProfileId ?? ""}
          profiles={authProfiles}
          onSave={(value) => updateSettings({ portalAuthenticationProfileId: value || null })}
        />
      )}

      {activeTab === "admin" && (
        <SettingsPanel
          key={config.settings.adminAuthenticationProfileId ?? "admin-disabled"}
          title="Admin Login"
          value={config.settings.adminAuthenticationProfileId ?? ""}
          profiles={adminAuthProfiles}
          onSave={(value) => updateSettings({ adminAuthenticationProfileId: value || null })}
        />
      )}

      {activeTab === "sessions" && (
        <Panel title="Active Sessions" action={<IconButton icon="lucide:refresh-cw" label="Refresh" onClick={() => void refetch()} />}>
          <SessionsTable
            sessions={sessions}
            loading={sessionsFetching}
            onRevoke={(session) => {
              if (!window.confirm(`Revoke identity session for ${session.username} (${session.sourceIp})?`)) return;
              void runAction(() => revokeIdentitySession({ sessionId: session.sessionId, sourceIp: session.sourceIp }).unwrap(), "Identity session revoked");
            }}
          />
        </Panel>
      )}

      {activeTab === "diagnostics" && (
        <DiagnosticsPanel
          radiusProfiles={radiusProfiles}
          ldapProfiles={ldapProfiles}
          state={testState}
          onChange={setTestState}
          onRadiusTest={runRadiusTest}
          onLdapTest={runLdapTest}
          radiusName={(id) => radiusProfileById.get(id)?.name ?? "RADIUS"}
          ldapName={(id) => ldapProfileById.get(id)?.name ?? "LDAP"}
        />
      )}
    </IdentityShell>
  );
}

function IdentityShell({
  activeTab,
  onTabChange,
  children,
}: {
  activeTab: TabKey;
  onTabChange: (tab: TabKey) => void;
  children: ReactNode;
}) {
  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col text-[#f5f5f5]">
      <div className="flex-1 flex justify-center p-8">
        <div className="w-full max-w-[100rem]">
          <div className="flex flex-col gap-2 mb-6">
            <div className="text-xs uppercase tracking-[0.22em] text-[#06b6d4]">Identity</div>
            <div className="flex items-center justify-between gap-4">
              <h1 className="text-2xl font-light">Identity providers and access sessions</h1>
              <div className="text-xs text-[#8a8a8a]">RADIUS / LDAP / Portal / Admin Login</div>
            </div>
          </div>
          <div className="border border-[#262626] bg-[#111] mb-4 overflow-x-auto">
            <div className="flex min-w-max">
              {tabs.map((tab) => (
                <button
                  key={tab.key}
                  type="button"
                  onClick={() => onTabChange(tab.key)}
                  className={`flex items-center gap-2 px-4 py-3 text-sm border-r border-[#262626] transition-colors ${
                    activeTab === tab.key
                      ? "text-[#06b6d4] bg-[#06b6d4]/10"
                      : "text-[#8a8a8a] hover:text-[#f5f5f5]"
                  }`}
                >
                  <Icon icon={tab.icon} width={16} height={16} />
                  {tab.label}
                </button>
              ))}
            </div>
          </div>
          {children}
        </div>
      </div>
    </div>
  );
}

function StatusBar({
  radiusCount,
  ldapCount,
  authCount,
  sessionCount,
  portalProfile,
  adminProfile,
}: {
  radiusCount: number;
  ldapCount: number;
  authCount: number;
  sessionCount: number;
  portalProfile: string;
  adminProfile: string;
}) {
  const items = [
    ["RADIUS", String(radiusCount)],
    ["LDAP", String(ldapCount)],
    ["AUTH PROFILES", String(authCount)],
    ["ACTIVE SESSIONS", String(sessionCount)],
    ["PORTAL", portalProfile],
    ["ADMIN", adminProfile],
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-6 gap-3 mb-4">
      {items.map(([label, value]) => (
        <div key={label} className="border border-[#262626] bg-[#161616] px-4 py-3">
          <div className="text-[11px] text-[#8a8a8a] tracking-widest">{label}</div>
          <div className="text-sm text-[#f5f5f5] mt-1 truncate">{value}</div>
        </div>
      ))}
    </div>
  );
}

function Panel({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="border border-[#262626] bg-[#161616]">
      <div className="flex items-center justify-between gap-4 px-4 py-3 border-b border-[#262626]">
        <div className="text-xs uppercase tracking-widest text-[#8a8a8a]">{title}</div>
        {action}
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

function IconButton({ icon, label, onClick }: { icon: string; label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-2 border border-[#262626] px-3 py-2 text-xs text-[#8a8a8a] hover:border-[#06b6d4] hover:text-[#f5f5f5]"
    >
      <Icon icon={icon} width={14} height={14} />
      {label}
    </button>
  );
}

function ProfileTable({
  rows,
  empty,
}: {
  empty: string;
  rows: {
    id: string;
    name: string;
    status: string;
    primary: string;
    secondary: string;
    meta: string;
    onEdit: () => void;
    onDelete: () => void;
  }[];
}) {
  if (rows.length === 0) return <EmptyState text={empty} />;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="text-[#8a8a8a] border-b border-[#262626]">
          <tr>
            <th className="text-left font-normal py-2 pr-4">Name</th>
            <th className="text-left font-normal py-2 pr-4">Endpoint</th>
            <th className="text-left font-normal py-2 pr-4">Reference</th>
            <th className="text-left font-normal py-2 pr-4">Meta</th>
            <th className="text-right font-normal py-2">Actions</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className="border-b border-[#202020]">
              <td className="py-3 pr-4">
                <div className="text-[#f5f5f5]">{row.name}</div>
                <div className={`text-xs ${row.status === "active" ? "text-[#10b981]" : "text-[#8a8a8a]"}`}>{row.status}</div>
              </td>
              <td className="py-3 pr-4 text-[#d4d4d4]">{row.primary}</td>
              <td className="py-3 pr-4 text-[#8a8a8a] break-all">{row.secondary}</td>
              <td className="py-3 pr-4 text-[#8a8a8a]">{row.meta}</td>
              <td className="py-3">
                <div className="flex justify-end gap-2">
                  <IconButton icon="lucide:pencil" label="Edit" onClick={row.onEdit} />
                  <IconButton icon="lucide:trash-2" label="Delete" onClick={row.onDelete} />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RadiusProfileForm({
  form,
  onChange,
  onSave,
  onCancel,
}: {
  form: RadiusForm;
  onChange: (form: RadiusForm) => void;
  onSave: () => void;
  onCancel: () => void;
}) {
  const update = <K extends keyof RadiusForm>(key: K, value: RadiusForm[K]) =>
    onChange({ ...form, [key]: value });
  const handleNameChange = (value: string) => {
    const previousAutoRef = `secret://identity/radius/${slug(form.name)}`;
    const shouldUpdateRef =
      !form.id &&
      (form.sharedSecretRef === "secret://identity/radius/default" ||
        form.sharedSecretRef === previousAutoRef);
    onChange({
      ...form,
      name: value,
      sharedSecretRef: shouldUpdateRef
        ? `secret://identity/radius/${slug(value)}`
        : form.sharedSecretRef,
    });
  };

  return (
    <Panel title={form.id ? "Edit RADIUS Profile" : "New RADIUS Profile"}>
      <FormGrid>
        <TextField label="Name" value={form.name} onChange={handleNameChange} />
        <TextField label="Description" value={form.description ?? ""} onChange={(value) => update("description", toNullable(value))} />
        <CheckField label="Active" checked={form.isActive} onChange={(value) => update("isActive", value)} />
        <TextField label="Host" value={form.host} onChange={(value) => update("host", value)} />
        <NumberField label="Port" value={form.port} onChange={(value) => update("port", value)} />
        <NumberField label="Timeout ms" value={form.timeoutMs} onChange={(value) => update("timeoutMs", value)} />
        <NumberField label="Retries" value={form.retries} onChange={(value) => update("retries", value)} />
        <TextField label="Shared secret ref" value={form.sharedSecretRef} onChange={(value) => update("sharedSecretRef", value)} />
        <TextField label="Set shared secret" value={form.secretValue} type="password" onChange={(value) => update("secretValue", value)} />
        <TextField label="NAS IP" value={form.nasIp ?? ""} onChange={(value) => update("nasIp", toNullable(value))} />
        <TextField label="NAS identifier" value={form.nasIdentifier ?? ""} onChange={(value) => update("nasIdentifier", toNullable(value))} />
        <TextField label="Called station ID" value={form.calledStationId ?? ""} onChange={(value) => update("calledStationId", toNullable(value))} />
      </FormGrid>
      <FormActions onSave={onSave} onCancel={onCancel} />
    </Panel>
  );
}

function LdapProfileForm({
  form,
  onChange,
  onSave,
  onCancel,
}: {
  form: LdapForm;
  onChange: (form: LdapForm) => void;
  onSave: () => void;
  onCancel: () => void;
}) {
  const update = <K extends keyof LdapForm>(key: K, value: LdapForm[K]) =>
    onChange({ ...form, [key]: value });
  const handleNameChange = (value: string) => {
    const previousAutoRef = `secret://identity/ldap/${slug(form.name)}`;
    const shouldUpdateRef =
      !form.id &&
      (form.bindPasswordRef === "secret://identity/ldap/default" ||
        form.bindPasswordRef === previousAutoRef);
    onChange({
      ...form,
      name: value,
      bindPasswordRef: shouldUpdateRef
        ? `secret://identity/ldap/${slug(value)}`
        : form.bindPasswordRef,
    });
  };

  return (
    <Panel title={form.id ? "Edit LDAP Profile" : "New LDAP Profile"}>
      <FormGrid>
        <TextField label="Name" value={form.name} onChange={handleNameChange} />
        <TextField label="Description" value={form.description ?? ""} onChange={(value) => update("description", toNullable(value))} />
        <CheckField label="Active" checked={form.isActive} onChange={(value) => update("isActive", value)} />
        <TextField label="Host" value={form.host} onChange={(value) => update("host", value)} />
        <NumberField label="Port" value={form.port} onChange={(value) => update("port", value)} />
        <SelectField label="TLS mode" value={form.tlsMode} options={["disabled", "starttls", "ldaps"]} onChange={(value) => update("tlsMode", value as LdapTlsMode)} />
        <TextField label="Bind DN" value={form.bindDn} onChange={(value) => update("bindDn", value)} />
        <TextField label="Bind password ref" value={form.bindPasswordRef} onChange={(value) => update("bindPasswordRef", value)} />
        <TextField label="Set bind password" value={form.bindPasswordValue} type="password" onChange={(value) => update("bindPasswordValue", value)} />
        <TextField label="User base DN" value={form.userBaseDn} onChange={(value) => update("userBaseDn", value)} />
        <TextField label="User filter attribute" value={form.userFilterAttribute} onChange={(value) => update("userFilterAttribute", value)} />
        <TextField label="Group base DN" value={form.groupBaseDn} onChange={(value) => update("groupBaseDn", value)} />
        <TextField label="Group member attribute" value={form.groupMemberAttribute} onChange={(value) => update("groupMemberAttribute", value)} />
        <TextField label="Group name attribute" value={form.groupNameAttribute} onChange={(value) => update("groupNameAttribute", value)} />
        <NumberField label="Timeout ms" value={form.timeoutMs} onChange={(value) => update("timeoutMs", value)} />
        <NumberField label="Cache TTL seconds" value={form.cacheTtlSeconds} onChange={(value) => update("cacheTtlSeconds", value)} />
      </FormGrid>
      <FormActions onSave={onSave} onCancel={onCancel} />
    </Panel>
  );
}

function AuthProfileForm({
  form,
  onChange,
  onSave,
  onCancel,
  radiusProfiles,
  ldapProfiles,
}: {
  form: AuthForm;
  onChange: (form: AuthForm) => void;
  onSave: () => void;
  onCancel: () => void;
  radiusProfiles: RadiusServerProfile[];
  ldapProfiles: LdapServerProfile[];
}) {
  const update = <K extends keyof AuthForm>(key: K, value: AuthForm[K]) =>
    onChange({ ...form, [key]: value });
  const mappings = form.adminRoleMappings ?? [];

  const updateMapping = (index: number, patch: Partial<AdminRoleMapping>) => {
    const next = mappings.map((mapping, i) =>
      i === index ? { ...mapping, ...patch } : mapping,
    );
    update("adminRoleMappings", next);
  };

  return (
    <Panel title={form.id ? "Edit Authentication Profile" : "New Authentication Profile"}>
      <FormGrid>
        <TextField label="Name" value={form.name} onChange={(value) => update("name", value)} />
        <TextField label="Description" value={form.description ?? ""} onChange={(value) => update("description", toNullable(value))} />
        <CheckField label="Active" checked={form.isActive} onChange={(value) => update("isActive", value)} />
        <SelectField label="Provider" value={form.provider} options={["radius", "ldap", "local"]} onChange={(value) => update("provider", value as IdentityProvider)} />
        <SelectField label="RADIUS profile" value={form.radiusProfileId ?? ""} options={["", ...radiusProfiles.map((profile) => profile.id)]} labels={profileLabels(radiusProfiles, "None")} onChange={(value) => update("radiusProfileId", value || null)} />
        <SelectField label="LDAP profile" value={form.ldapProfileId ?? ""} options={["", ...ldapProfiles.map((profile) => profile.id)]} labels={profileLabels(ldapProfiles, "None")} onChange={(value) => update("ldapProfileId", value || null)} />
        <SelectField label="Group source" value={form.groupSource} options={["none", "ldap", "radius_vsa"]} onChange={(value) => update("groupSource", value as IdentityGroupSource)} />
        <NumberField label="Session TTL seconds" value={form.sessionTtlSeconds} onChange={(value) => update("sessionTtlSeconds", value)} />
      </FormGrid>
      <div className="mt-4 border-t border-[#262626] pt-4">
        <div className="flex items-center justify-between mb-3">
          <div className="text-xs uppercase tracking-widest text-[#8a8a8a]">Admin role mappings</div>
          <IconButton
            icon="lucide:plus"
            label="Add"
            onClick={() =>
              update("adminRoleMappings", [
                ...mappings,
                { matchType: "ldap_group", matchValue: "", role: "admin" },
              ])
            }
          />
        </div>
        <div className="space-y-2">
          {mappings.length === 0 && <EmptyState text="No admin role mappings" />}
          {mappings.map((mapping, index) => (
            <div key={`${mapping.matchType}-${index}`} className="grid grid-cols-1 md:grid-cols-[150px_minmax(0,1fr)_150px_42px] gap-2">
              <SelectField label="Match" value={mapping.matchType} options={matchTypeOptions} onChange={(value) => updateMapping(index, { matchType: value as AdminRoleMappingMatchType })} />
              <TextField label="Value" value={mapping.matchValue} onChange={(value) => updateMapping(index, { matchValue: value })} />
              <SelectField label="Role" value={mapping.role} options={roleOptions} onChange={(value) => updateMapping(index, { role: value as AdminRole })} />
              <button
                type="button"
                onClick={() => update("adminRoleMappings", mappings.filter((_, i) => i !== index))}
                className="self-end h-[42px] border border-[#262626] text-[#8a8a8a] hover:text-[#ef4444] hover:border-[#ef4444]"
              >
                <Icon icon="lucide:x" className="mx-auto" />
              </button>
            </div>
          ))}
        </div>
      </div>
      <FormActions onSave={onSave} onCancel={onCancel} />
    </Panel>
  );
}

function SettingsPanel({
  title,
  value,
  profiles,
  onSave,
}: {
  title: string;
  value: string;
  profiles: IdentityAuthenticationProfile[];
  onSave: (value: string) => Promise<void>;
}) {
  const [selected, setSelected] = useState(value);

  return (
    <Panel title={title}>
      <div className="max-w-xl">
        <SelectField
          label="Authentication profile"
          value={selected}
          options={["", ...profiles.map((profile) => profile.id)]}
          labels={profileLabels(profiles, "Disabled")}
          onChange={setSelected}
        />
        <div className="mt-4">
          <IconButton icon="lucide:save" label="Save settings" onClick={() => void onSave(selected)} />
        </div>
      </div>
    </Panel>
  );
}

function SessionsTable({
  sessions,
  loading,
  onRevoke,
}: {
  sessions: IdentitySession[];
  loading: boolean;
  onRevoke: (session: IdentitySession) => void;
}) {
  if (loading) return <StateLine icon="lucide:loader-2" text="Loading sessions" />;
  if (sessions.length === 0) return <EmptyState text="No active identity sessions" />;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="text-[#8a8a8a] border-b border-[#262626]">
          <tr>
            <th className="text-left font-normal py-2 pr-4">Source IP</th>
            <th className="text-left font-normal py-2 pr-4">Username</th>
            <th className="text-left font-normal py-2 pr-4">Groups</th>
            <th className="text-left font-normal py-2 pr-4">Created</th>
            <th className="text-left font-normal py-2 pr-4">Expires</th>
            <th className="text-right font-normal py-2">Action</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((session) => (
            <tr key={session.sessionId} className="border-b border-[#202020]">
              <td className="py-3 pr-4 text-[#f5f5f5]">{session.sourceIp}</td>
              <td className="py-3 pr-4">{session.username}</td>
              <td className="py-3 pr-4 text-[#8a8a8a]">{session.groups.join(", ") || "none"}</td>
              <td className="py-3 pr-4 text-[#8a8a8a]">{formatDate(session.createdAt)}</td>
              <td className="py-3 pr-4 text-[#8a8a8a]">{formatDate(session.expiresAt)}</td>
              <td className="py-3 text-right">
                <IconButton icon="lucide:log-out" label="Revoke" onClick={() => onRevoke(session)} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DiagnosticsPanel({
  radiusProfiles,
  ldapProfiles,
  state,
  onChange,
  onRadiusTest,
  onLdapTest,
  radiusName,
  ldapName,
}: {
  radiusProfiles: RadiusServerProfile[];
  ldapProfiles: LdapServerProfile[];
  state: TestState;
  onChange: (state: TestState) => void;
  onRadiusTest: () => void;
  onLdapTest: () => void;
  radiusName: (id: string) => string;
  ldapName: (id: string) => string;
}) {
  const update = <K extends keyof TestState>(key: K, value: TestState[K]) =>
    onChange({ ...state, [key]: value });

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
      <Panel title="RADIUS Test">
        <FormGrid>
          <SelectField label="Profile" value={state.radiusProfileId} options={radiusProfiles.map((profile) => profile.id)} labels={new Map(radiusProfiles.map((profile) => [profile.id, profile.name]))} onChange={(value) => update("radiusProfileId", value)} />
          <TextField label="Username" value={state.radiusUsername} onChange={(value) => update("radiusUsername", value)} />
          <TextField label="Password" type="password" value={state.radiusPassword} onChange={(value) => update("radiusPassword", value)} />
          <TextField label="Calling station ID" value={state.radiusCallingStationId} onChange={(value) => update("radiusCallingStationId", value)} />
        </FormGrid>
        <div className="mt-4">
          <IconButton icon="lucide:activity" label={`Test ${radiusName(state.radiusProfileId)}`} onClick={() => void onRadiusTest()} />
        </div>
      </Panel>
      <Panel title="LDAP Test">
        <FormGrid>
          <SelectField label="Profile" value={state.ldapProfileId} options={ldapProfiles.map((profile) => profile.id)} labels={new Map(ldapProfiles.map((profile) => [profile.id, profile.name]))} onChange={(value) => update("ldapProfileId", value)} />
          <TextField label="Username" value={state.ldapUsername} onChange={(value) => update("ldapUsername", value)} />
        </FormGrid>
        <div className="mt-4">
          <IconButton icon="lucide:activity" label={`Test ${ldapName(state.ldapProfileId)}`} onClick={() => void onLdapTest()} />
        </div>
      </Panel>
      <div className="xl:col-span-2">
        <Panel title="Last Result">
          {state.result ? (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-sm">
              <Metric label="Result" value={state.result.result} />
              <Metric label="Latency" value={`${state.result.latencyMs} ms`} />
              <Metric label="Message" value={state.result.message} />
              <Metric label="Groups" value={state.result.groups?.join(", ") || state.result.userDn || "none"} />
            </div>
          ) : (
            <EmptyState text="No diagnostic result" />
          )}
        </Panel>
      </div>
    </div>
  );
}

function FormGrid({ children }: { children: ReactNode }) {
  return <div className="grid grid-cols-1 md:grid-cols-2 gap-3">{children}</div>;
}

function TextField({
  label,
  value,
  onChange,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
}) {
  return (
    <label className="block">
      <span className="block text-xs text-[#8a8a8a] mb-1">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full bg-[#0c0c0c] border border-[#262626] px-3 py-2 text-sm text-white focus:outline-none focus:border-[#06b6d4]"
      />
    </label>
  );
}

function NumberField({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) {
  return (
    <TextField
      label={label}
      value={String(value)}
      type="number"
      onChange={(next) => onChange(Number.parseInt(next, 10) || 0)}
    />
  );
}

function SelectField({
  label,
  value,
  options,
  labels,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  labels?: Map<string, string>;
  onChange: (value: string) => void;
}) {
  return (
    <label className="block">
      <span className="block text-xs text-[#8a8a8a] mb-1">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full bg-[#0c0c0c] border border-[#262626] px-3 py-2 text-sm text-white focus:outline-none focus:border-[#06b6d4]"
      >
        {options.map((option) => (
          <option key={option || "empty"} value={option}>
            {labels?.get(option) ?? option}
          </option>
        ))}
      </select>
    </label>
  );
}

function CheckField({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <label className="flex items-center gap-3 text-sm text-[#d4d4d4] mt-6">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="accent-[#06b6d4]"
      />
      {label}
    </label>
  );
}

function FormActions({ onSave, onCancel }: { onSave: () => void; onCancel: () => void }) {
  return (
    <div className="flex justify-end gap-2 mt-4">
      <IconButton icon="lucide:rotate-ccw" label="Reset" onClick={onCancel} />
      <IconButton icon="lucide:save" label="Save" onClick={() => void onSave()} />
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return <div className="border border-dashed border-[#262626] py-8 text-center text-sm text-[#8a8a8a]">{text}</div>;
}

function StateLine({ icon, text }: { icon: string; text: string }) {
  return (
    <div className="flex items-center gap-3 text-sm text-[#8a8a8a]">
      <Icon icon={icon} width={18} height={18} />
      {text}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="border border-[#262626] bg-[#0c0c0c] p-3">
      <div className="text-[11px] text-[#8a8a8a] tracking-widest">{label}</div>
      <div className="text-sm mt-1 break-words">{value}</div>
    </div>
  );
}

function defaultRadiusForm(): RadiusForm {
  return {
    id: null,
    name: "",
    description: null,
    isActive: true,
    host: "",
    port: 1812,
    sharedSecretRef: "secret://identity/radius/default",
    secretValue: "",
    timeoutMs: 3000,
    retries: 1,
    nasIp: null,
    nasIdentifier: null,
    calledStationId: null,
  };
}

function defaultLdapForm(): LdapForm {
  return {
    id: null,
    name: "",
    description: null,
    isActive: true,
    host: "",
    port: 389,
    tlsMode: "disabled",
    bindDn: "",
    bindPasswordRef: "secret://identity/ldap/default",
    bindPasswordValue: "",
    userBaseDn: "",
    userFilterAttribute: "uid",
    groupBaseDn: "",
    groupMemberAttribute: "memberUid",
    groupNameAttribute: "cn",
    timeoutMs: 3000,
    cacheTtlSeconds: 300,
  };
}

function defaultAuthForm(): AuthForm {
  return {
    id: null,
    name: "",
    description: null,
    isActive: true,
    provider: "radius",
    radiusProfileId: null,
    ldapProfileId: null,
    groupSource: "none",
    sessionTtlSeconds: 1800,
    adminRoleMappings: [],
  };
}

function radiusFormFromProfile(profile: RadiusServerProfile): RadiusForm {
  return {
    ...profile,
    description: profile.description,
    secretValue: "",
  };
}

function ldapFormFromProfile(profile: LdapServerProfile): LdapForm {
  return {
    ...profile,
    description: profile.description,
    bindPasswordValue: "",
  };
}

function authFormFromProfile(profile: IdentityAuthenticationProfile): AuthForm {
  return {
    id: profile.id,
    name: profile.name,
    description: profile.description,
    isActive: profile.isActive,
    provider: profile.provider,
    radiusProfileId: profile.radiusProfileId,
    ldapProfileId: profile.ldapProfileId,
    groupSource: profile.groupSource,
    sessionTtlSeconds: profile.sessionTtlSeconds,
    adminRoleMappings: profile.adminRoleMappings,
  };
}

function radiusBody(form: RadiusForm): RadiusProfileBody {
  return {
    name: form.name,
    description: form.description,
    isActive: form.isActive,
    host: form.host,
    port: form.port,
    sharedSecretRef: form.sharedSecretRef,
    timeoutMs: form.timeoutMs,
    retries: form.retries,
    nasIp: form.nasIp,
    nasIdentifier: form.nasIdentifier,
    calledStationId: form.calledStationId,
  };
}

function ldapBody(form: LdapForm): LdapProfileBody {
  return {
    name: form.name,
    description: form.description,
    isActive: form.isActive,
    host: form.host,
    port: form.port,
    tlsMode: form.tlsMode,
    bindDn: form.bindDn,
    bindPasswordRef: form.bindPasswordRef,
    userBaseDn: form.userBaseDn,
    userFilterAttribute: form.userFilterAttribute,
    groupBaseDn: form.groupBaseDn,
    groupMemberAttribute: form.groupMemberAttribute,
    groupNameAttribute: form.groupNameAttribute,
    timeoutMs: form.timeoutMs,
    cacheTtlSeconds: form.cacheTtlSeconds,
  };
}

function authBody(form: AuthForm): AuthenticationProfileBody {
  return {
    name: form.name,
    description: form.description,
    isActive: form.isActive,
    provider: form.provider,
    radiusProfileId: form.radiusProfileId,
    ldapProfileId: form.ldapProfileId,
    groupSource: form.groupSource,
    sessionTtlSeconds: form.sessionTtlSeconds,
    adminRoleMappings: form.adminRoleMappings?.filter(
      (mapping) => mapping.matchValue.trim().length > 0,
    ),
  };
}

async function upsertSecretIfNeeded(
  ref: string,
  value: string,
  upsertSecret: (body: { scope: string; type: string; name: string; value: string }) => {
    unwrap: () => Promise<unknown>;
  },
) {
  if (!value) return;
  const path = secretPathFromRef(ref);
  await upsertSecret({ ...path, value }).unwrap();
}

function secretPathFromRef(ref: string): { scope: string; type: string; name: string } {
  const match = /^secret:\/\/([^/]+)\/([^/]+)\/([^/]+)$/.exec(ref);
  if (!match) throw new Error("Secret ref must use secret://scope/type/name");
  return { scope: match[1], type: match[2], name: match[3] };
}

function profileName<T extends { id: string; name: string }>(
  id: string | null,
  profiles: T[],
): string {
  if (!id) return "disabled";
  return profiles.find((profile) => profile.id === id)?.name ?? id;
}

function profileLabels<T extends { id: string; name: string }>(
  profiles: T[],
  empty: string,
): Map<string, string> {
  return new Map([["", empty], ...profiles.map((profile) => [profile.id, profile.name] as [string, string])]);
}

function formatDate(raw: string): string {
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? raw : date.toLocaleString();
}

function toNullable(value: string): string | null {
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function slug(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "default";
}

function errorMessage(err: unknown): string {
  if (typeof err === "object" && err !== null) {
    const candidate = err as { data?: ApiFailure; message?: string };
    return candidate.data?.message ?? candidate.message ?? "Request failed";
  }
  return "Request failed";
}
