import { createApi } from "@reduxjs/toolkit/query/react";
import type { ConfigSnapshot, SnapshotType } from "../types/config/Config";
import { baseQueryWithReauth } from "./baseQueryWithReauth";
import type { ApiResponse } from "../types/ApiResponse";
import type { ConfigDiffResult } from "../types/config/ConfigDiff";

export type CreateConfigBody = {
  snapshotType: SnapshotType;
  isActive: boolean;
  payloadJson: Record<string, unknown>;
  changeSummary?: string;
};

export type GetConfigHistoryPayload = {
  configHistory: ConfigSnapshot[];
};

export type GetConfigDiffParams = {
  baseId: string;
  targetId: string;
};

export type ApplyConfigBody = {
  snapshotType: SnapshotType;
  isActive: boolean;
  changeSummary?: string | null;
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

    getConfigHistory: builder.query<ApiResponse<GetConfigHistoryPayload>, void>(
      {
        query: () => ({
          url: "/config/history",
          method: "GET",
        }),
      },
    ),

    applyConfig: builder.mutation<ApiResponse<ConfigSnapshot>, ApplyConfigBody>({
      query: (body) => ({
        url: "/config/apply",
        method: "POST",
        body,
      }),
    }),

    getConfigDiff: builder.query<ApiResponse<ConfigDiffResult>, GetConfigDiffParams>(
      {
        query: ({ baseId, targetId }) => ({
          url: "/config/diff",
          method: "GET",
          params: { baseId, targetId },
        }),
      },
    ),
  }),
});

export const {
  useExportConfigQuery,
  useImportConfigMutation,
  useApplyConfigMutation,
  useGetConfigHistoryQuery,
  useGetConfigDiffQuery,
} = configApi;
