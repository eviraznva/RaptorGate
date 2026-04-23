import { createApi } from "@reduxjs/toolkit/query/react";
import type { ConfigSnapshot, SnapshotType } from "../types/config/Config";
import { baseQueryWithReauth } from "./baseQueryWithReauth";
import type { ApiResponse } from "../types/ApiResponse";

export type CreateConfigBody = {
  snapshotType: SnapshotType;
  isActive: boolean;
  payloadJson: Record<string, unknown>;
  changeSummary?: string;
};

export const configApi = createApi({
  reducerPath: "configApi",
  baseQuery: baseQueryWithReauth,
  endpoints: (builder) => ({
    exportConfig: builder.query<ApiResponse<ConfigSnapshot>, void>({
      query: () => ({
        url: "/config/export",
        method: "GET",
      }),
    }),

    importConfig: builder.mutation<ApiResponse<ConfigSnapshot>, ConfigSnapshot>(
      {
        query: (config) => ({
          url: "/config/import",
          method: "POST",
          body: config,
        }),
      },
    ),
  }),
});

export const { useExportConfigQuery, useImportConfigMutation } = configApi;
