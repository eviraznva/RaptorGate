import { createApi } from "@reduxjs/toolkit/query/react";
import type { ApiResponse } from "../types/ApiResponse";
import type {
  ClearDecryptionExclusionsPayload,
  DecryptionExclusionListPayload,
  DecryptionExclusionStatsPayload,
} from "../types/ssl/DecryptionExclusion";
import { baseQueryWithReauth } from "./baseQueryWithReauth";

export const decryptionExclusionsApi = createApi({
  reducerPath: "decryptionExclusionsApi",
  baseQuery: baseQueryWithReauth,
  tagTypes: ["DecryptionExclusions"],
  endpoints: (builder) => ({
    getDecryptionExclusionStats: builder.query<
      ApiResponse<DecryptionExclusionStatsPayload>,
      void
    >({
      query: () => ({
        url: "/tls/decryption-exclusions/stats",
        method: "GET",
      }),
      providesTags: ["DecryptionExclusions"],
    }),

    listDecryptionExclusions: builder.query<
      ApiResponse<DecryptionExclusionListPayload>,
      void
    >({
      query: () => ({
        url: "/tls/decryption-exclusions",
        method: "GET",
      }),
      providesTags: ["DecryptionExclusions"],
    }),

    clearDecryptionExclusions: builder.mutation<
      ApiResponse<ClearDecryptionExclusionsPayload>,
      void
    >({
      query: () => ({
        url: "/tls/decryption-exclusions",
        method: "DELETE",
      }),
      invalidatesTags: ["DecryptionExclusions"],
    }),
  }),
});

export const {
  useGetDecryptionExclusionStatsQuery,
  useListDecryptionExclusionsQuery,
  useClearDecryptionExclusionsMutation,
} = decryptionExclusionsApi;
