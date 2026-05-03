import { createApi } from "@reduxjs/toolkit/query/react";
import type { ApiResponse } from "../types/ApiResponse";
import type {
  AdminRoleMapping,
  IdentityConfig,
  IdentityGroupSource,
  IdentityProvider,
  IdentityProviderTestResult,
  LdapTlsMode,
} from "../types/identity/IdentityConfig";
import { baseQueryWithReauth } from "./baseQueryWithReauth";

export type RadiusProfileBody = {
  name: string;
  description: string | null;
  isActive: boolean;
  host: string;
  port: number;
  sharedSecretRef: string;
  timeoutMs: number;
  retries: number;
  nasIp: string | null;
  nasIdentifier: string | null;
  calledStationId: string | null;
};

export type LdapProfileBody = {
  name: string;
  description: string | null;
  isActive: boolean;
  host: string;
  port: number;
  tlsMode: LdapTlsMode;
  bindDn: string;
  bindPasswordRef: string;
  userBaseDn: string;
  userFilterAttribute: string;
  groupBaseDn: string;
  groupMemberAttribute: string;
  groupNameAttribute: string;
  timeoutMs: number;
  cacheTtlSeconds: number;
};

export type AuthenticationProfileBody = {
  name: string;
  description: string | null;
  isActive: boolean;
  provider: IdentityProvider;
  radiusProfileId: string | null;
  ldapProfileId: string | null;
  groupSource: IdentityGroupSource;
  sessionTtlSeconds: number;
  adminRoleMappings?: AdminRoleMapping[];
};

export type IdentitySettingsPatch = {
  portalAuthenticationProfileId?: string | null;
  adminAuthenticationProfileId?: string | null;
  portalListener?: {
    enabled?: boolean;
    interfaceName?: string | null;
    zoneId?: string | null;
    bindAddress?: string | null;
    bindPort?: number;
  };
};

export type TestRadiusProfileBody = {
  username: string;
  password: string;
  callingStationId?: string;
};

export type TestLdapProfileBody = {
  username: string;
};

export const identityConfigApi = createApi({
  reducerPath: "identityConfigApi",
  baseQuery: baseQueryWithReauth,
  tagTypes: ["IdentityConfig"],
  endpoints: (builder) => ({
    getIdentityConfig: builder.query<ApiResponse<IdentityConfig>, void>({
      query: () => ({
        url: "/identity-config",
        method: "GET",
      }),
      providesTags: ["IdentityConfig"],
    }),

    createRadiusProfile: builder.mutation<ApiResponse<IdentityConfig>, RadiusProfileBody>({
      query: (body) => ({
        url: "/identity-config/radius-profiles",
        method: "POST",
        body,
      }),
      invalidatesTags: ["IdentityConfig"],
    }),

    updateRadiusProfile: builder.mutation<ApiResponse<IdentityConfig>, { id: string } & RadiusProfileBody>({
      query: ({ id, ...body }) => ({
        url: `/identity-config/radius-profiles/${id}`,
        method: "PUT",
        body,
      }),
      invalidatesTags: ["IdentityConfig"],
    }),

    deleteRadiusProfile: builder.mutation<void, string>({
      query: (id) => ({
        url: `/identity-config/radius-profiles/${id}`,
        method: "DELETE",
      }),
      invalidatesTags: ["IdentityConfig"],
    }),

    testRadiusProfile: builder.mutation<ApiResponse<IdentityProviderTestResult>, { id: string } & TestRadiusProfileBody>({
      query: ({ id, ...body }) => ({
        url: `/identity-config/radius-profiles/${id}/test`,
        method: "POST",
        body,
      }),
    }),

    createLdapProfile: builder.mutation<ApiResponse<IdentityConfig>, LdapProfileBody>({
      query: (body) => ({
        url: "/identity-config/ldap-profiles",
        method: "POST",
        body,
      }),
      invalidatesTags: ["IdentityConfig"],
    }),

    updateLdapProfile: builder.mutation<ApiResponse<IdentityConfig>, { id: string } & LdapProfileBody>({
      query: ({ id, ...body }) => ({
        url: `/identity-config/ldap-profiles/${id}`,
        method: "PUT",
        body,
      }),
      invalidatesTags: ["IdentityConfig"],
    }),

    deleteLdapProfile: builder.mutation<void, string>({
      query: (id) => ({
        url: `/identity-config/ldap-profiles/${id}`,
        method: "DELETE",
      }),
      invalidatesTags: ["IdentityConfig"],
    }),

    testLdapProfile: builder.mutation<ApiResponse<IdentityProviderTestResult>, { id: string } & TestLdapProfileBody>({
      query: ({ id, ...body }) => ({
        url: `/identity-config/ldap-profiles/${id}/test`,
        method: "POST",
        body,
      }),
    }),

    createAuthenticationProfile: builder.mutation<ApiResponse<IdentityConfig>, AuthenticationProfileBody>({
      query: (body) => ({
        url: "/identity-config/authentication-profiles",
        method: "POST",
        body,
      }),
      invalidatesTags: ["IdentityConfig"],
    }),

    updateAuthenticationProfile: builder.mutation<ApiResponse<IdentityConfig>, { id: string } & AuthenticationProfileBody>({
      query: ({ id, ...body }) => ({
        url: `/identity-config/authentication-profiles/${id}`,
        method: "PUT",
        body,
      }),
      invalidatesTags: ["IdentityConfig"],
    }),

    deleteAuthenticationProfile: builder.mutation<void, string>({
      query: (id) => ({
        url: `/identity-config/authentication-profiles/${id}`,
        method: "DELETE",
      }),
      invalidatesTags: ["IdentityConfig"],
    }),

    updateIdentitySettings: builder.mutation<ApiResponse<IdentityConfig>, IdentitySettingsPatch>({
      query: (body) => ({
        url: "/identity-config/settings",
        method: "PATCH",
        body,
      }),
      invalidatesTags: ["IdentityConfig"],
    }),
  }),
});

export const {
  useGetIdentityConfigQuery,
  useCreateRadiusProfileMutation,
  useUpdateRadiusProfileMutation,
  useDeleteRadiusProfileMutation,
  useTestRadiusProfileMutation,
  useCreateLdapProfileMutation,
  useUpdateLdapProfileMutation,
  useDeleteLdapProfileMutation,
  useTestLdapProfileMutation,
  useCreateAuthenticationProfileMutation,
  useUpdateAuthenticationProfileMutation,
  useDeleteAuthenticationProfileMutation,
  useUpdateIdentitySettingsMutation,
} = identityConfigApi;
