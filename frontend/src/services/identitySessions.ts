import { createApi } from "@reduxjs/toolkit/query/react";
import type { ApiResponse } from "../types/ApiResponse";
import type { IdentitySession } from "../types/identity/IdentitySession";
import { baseQueryWithReauth } from "./baseQueryWithReauth";

export type IdentitySessionsPayload = {
  identitySessions: IdentitySession[];
};

export type RevokeIdentitySessionBody = {
  sessionId?: string;
  sourceIp?: string;
};

export type RevokeIdentitySessionResult = {
  removed: boolean;
};

export const identitySessionsApi = createApi({
  reducerPath: "identitySessionsApi",
  baseQuery: baseQueryWithReauth,
  tagTypes: ["IdentitySessions"],
  endpoints: (builder) => ({
    getIdentitySessions: builder.query<ApiResponse<IdentitySessionsPayload>, void>({
      query: () => ({
        url: "/identity-sessions",
        method: "GET",
      }),
      providesTags: ["IdentitySessions"],
    }),

    revokeIdentitySession: builder.mutation<ApiResponse<RevokeIdentitySessionResult>, RevokeIdentitySessionBody>({
      query: (body) => ({
        url: "/identity-sessions/revoke",
        method: "POST",
        body,
      }),
      invalidatesTags: ["IdentitySessions"],
    }),
  }),
});

export const {
  useGetIdentitySessionsQuery,
  useRevokeIdentitySessionMutation,
} = identitySessionsApi;
