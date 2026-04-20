import { createApi } from "@reduxjs/toolkit/query/react";
import type { ApiResponse } from "../types/ApiResponse";
import type { DnsInspectionConfig } from "../types/dnsInspection/DnsInspectionConfig";
import { baseQueryWithReauth } from "./baseQueryWithReauth";

type DnsInspectionPayload = {
  dnsInspection: DnsInspectionConfig;
};

export const dnsInspectionApi = createApi({
  reducerPath: "dnsInspectionApi",
  baseQuery: baseQueryWithReauth,
  tagTypes: ["DnsInspection"],
  endpoints: (builder) => ({
    getDnsInspectionConfig: builder.query<
      ApiResponse<DnsInspectionPayload>,
      void
    >({
      query: () => ({
        url: "/dns-inspection",
        method: "GET",
      }),
      providesTags: ["DnsInspection"],
    }),

    updateDnsInspectionConfig: builder.mutation<
      ApiResponse<DnsInspectionPayload>,
      DnsInspectionConfig
    >({
      query: (dnsInspection) => ({
        url: "/dns-inspection",
        method: "PUT",
        body: dnsInspection,
      }),
      invalidatesTags: ["DnsInspection"],
    }),
  }),
});

export const {
  useGetDnsInspectionConfigQuery,
  useUpdateDnsInspectionConfigMutation,
} = dnsInspectionApi;
