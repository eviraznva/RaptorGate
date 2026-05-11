import { createApi } from "@reduxjs/toolkit/query/react";
import type { ApiResponse } from "../types/ApiResponse";
import type {
  DecryptionMirrorConfig,
  DecryptionMirrorPayload,
} from "../types/ssl/DecryptionMirror";
import { baseQueryWithReauth } from "./baseQueryWithReauth";

export const decryptionMirrorApi = createApi({
  reducerPath: "decryptionMirrorApi",
  baseQuery: baseQueryWithReauth,
  tagTypes: ["DecryptionMirror"],
  endpoints: (builder) => ({
    getDecryptionMirrorConfig: builder.query<
      ApiResponse<DecryptionMirrorPayload>,
      void
    >({
      query: () => ({
        url: "/ssl/decryption-mirror",
        method: "GET",
      }),
      providesTags: ["DecryptionMirror"],
    }),

    updateDecryptionMirrorConfig: builder.mutation<
      ApiResponse<DecryptionMirrorPayload>,
      DecryptionMirrorConfig
    >({
      query: (decryptionMirror) => ({
        url: "/ssl/decryption-mirror",
        method: "PUT",
        body: decryptionMirror,
      }),
      invalidatesTags: ["DecryptionMirror"],
    }),
  }),
});

export const {
  useGetDecryptionMirrorConfigQuery,
  useUpdateDecryptionMirrorConfigMutation,
} = decryptionMirrorApi;
