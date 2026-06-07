import { createApi } from "@reduxjs/toolkit/query/react";
import type { ApiResponse } from "../types/ApiResponse";
import type {
  DecryptionFailurePolicy,
  DecryptionFailurePolicyPayload,
} from "../types/ssl/DecryptionFailurePolicy";
import { baseQueryWithReauth } from "./baseQueryWithReauth";

export const decryptionFailurePolicyApi = createApi({
  reducerPath: "decryptionFailurePolicyApi",
  baseQuery: baseQueryWithReauth,
  tagTypes: ["DecryptionFailurePolicy"],
  endpoints: (builder) => ({
    getDecryptionFailurePolicy: builder.query<
      ApiResponse<DecryptionFailurePolicyPayload>,
      void
    >({
      query: () => ({
        url: "/ssl/decryption-failure-policy",
        method: "GET",
      }),
      providesTags: ["DecryptionFailurePolicy"],
    }),

    updateDecryptionFailurePolicy: builder.mutation<
      ApiResponse<DecryptionFailurePolicyPayload>,
      DecryptionFailurePolicy
    >({
      query: (decryptionFailurePolicy) => ({
        url: "/ssl/decryption-failure-policy",
        method: "PUT",
        body: decryptionFailurePolicy,
      }),
      invalidatesTags: ["DecryptionFailurePolicy"],
    }),
  }),
});

export const {
  useGetDecryptionFailurePolicyQuery,
  useUpdateDecryptionFailurePolicyMutation,
} = decryptionFailurePolicyApi;
