import { createApi } from "@reduxjs/toolkit/query/react";
import type { ApiResponse } from "../types/ApiResponse";
import type { SecretMetadata } from "../types/identity/Secret";
import { baseQueryWithReauth } from "./baseQueryWithReauth";

export type SecretPath = {
  scope: string;
  type: string;
  name: string;
};

export type UpsertSecretBody = SecretPath & {
  value: string;
};

export const secretsApi = createApi({
  reducerPath: "secretsApi",
  baseQuery: baseQueryWithReauth,
  tagTypes: ["Secret"],
  endpoints: (builder) => ({
    upsertSecret: builder.mutation<ApiResponse<SecretMetadata>, UpsertSecretBody>({
      query: ({ scope, type, name, value }) => ({
        url: `/secrets/${scope}/${type}/${name}`,
        method: "PUT",
        body: { value },
      }),
      invalidatesTags: ["Secret"],
    }),

    getSecretMetadata: builder.query<ApiResponse<SecretMetadata>, SecretPath>({
      query: ({ scope, type, name }) => ({
        url: `/secrets/${scope}/${type}/${name}`,
        method: "GET",
      }),
      providesTags: ["Secret"],
    }),
  }),
});

export const {
  useUpsertSecretMutation,
  useGetSecretMetadataQuery,
} = secretsApi;
