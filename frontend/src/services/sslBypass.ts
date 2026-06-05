import { createApi } from "@reduxjs/toolkit/query/react";
import type { ApiResponse } from "../types/ApiResponse";
import type {
  CreateSslBypassDomainPayload,
  CreateSslBypassDomainRequest,
  SslBypassDomainsPayload,
} from "../types/ssl/SslBypass";
import { baseQueryWithReauth } from "./baseQueryWithReauth";

export const sslBypassApi = createApi({
  reducerPath: "sslBypassApi",
  baseQuery: baseQueryWithReauth,
  tagTypes: ["SslBypass"],
  endpoints: (builder) => ({
    getSslBypassDomains: builder.query<
      ApiResponse<SslBypassDomainsPayload>,
      void
    >({
      query: () => ({
        url: "/ssl/bypass-domains",
        method: "GET",
      }),
      providesTags: ["SslBypass"],
    }),

    createSslBypassDomain: builder.mutation<
      ApiResponse<CreateSslBypassDomainPayload>,
      CreateSslBypassDomainRequest
    >({
      query: (body) => ({
        url: "/ssl/bypass-domains",
        method: "POST",
        body,
      }),
      invalidatesTags: ["SslBypass"],
    }),

    deleteSslBypassDomain: builder.mutation<void, string>({
      query: (id) => ({
        url: `/ssl/bypass-domains/${id}`,
        method: "DELETE",
      }),
      invalidatesTags: ["SslBypass"],
    }),
  }),
});

export const {
  useGetSslBypassDomainsQuery,
  useCreateSslBypassDomainMutation,
  useDeleteSslBypassDomainMutation,
} = sslBypassApi;
