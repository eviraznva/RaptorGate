import { createApi } from "@reduxjs/toolkit/query/react";
import type { ConfigSnapshot, SnapshotType } from "../types/config/Config";
import { baseQueryWithReauth } from "./baseQueryWithReauth";
import type { ApiFailure, ApiResponse, ApiSuccess } from "../types/ApiResponse";
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

export type RollbackConfigResponse = Omit<ConfigSnapshot, "changeSummary"> & {
  changeSummary?: string | null;
  changesSummary?: string | null;
};

type RawValueObject = {
  value?: unknown;
};

type RawConfigSnapshot = {
  id?: unknown;
  versionNumber?: unknown;
  snapshotType?: unknown;
  checksum?: unknown;
  isActive?: unknown;
  payloadJson?: unknown;
  changeSummary?: unknown;
  changesSummary?: unknown;
  createdAt?: unknown;
  createdBy?: unknown;
};

type RawConfigHistoryPayload = {
  configHistory?: RawConfigSnapshot[];
};

const snapshotTypes: SnapshotType[] = [
  "manual_import",
  "rollback_point",
  "auto_save",
];

function isSuccess<T>(response: ApiResponse<T>): response is ApiSuccess<T> {
  return "data" in response;
}

function readString(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }

  if (value && typeof value === "object" && "value" in value) {
    const rawValue = (value as RawValueObject).value;

    if (typeof rawValue === "string") {
      return rawValue;
    }
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  return "";
}

function readSnapshotType(value: unknown): SnapshotType {
  const snapshotType = readString(value);

  if (snapshotTypes.includes(snapshotType as SnapshotType)) {
    return snapshotType as SnapshotType;
  }

  return "manual_import";
}

function readPayloadJson(value: unknown): Record<string, unknown> {
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value) as unknown;

      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return {};
    }
  }

  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }

  return {};
}

function normalizeConfigSnapshot(snapshot: RawConfigSnapshot): ConfigSnapshot {
  const changeSummary = snapshot.changeSummary ?? snapshot.changesSummary;

  return {
    id: readString(snapshot.id),
    versionNumber:
      typeof snapshot.versionNumber === "number" ? snapshot.versionNumber : 0,
    snapshotType: readSnapshotType(snapshot.snapshotType),
    checksum: readString(snapshot.checksum),
    isActive: Boolean(snapshot.isActive),
    payloadJson: readPayloadJson(snapshot.payloadJson),
    changeSummary:
      typeof changeSummary === "string" ? changeSummary : null,
    createdAt: readString(snapshot.createdAt),
    createdBy: readString(snapshot.createdBy),
  };
}

function normalizeConfigHistoryResponse(
  response: ApiResponse<RawConfigHistoryPayload>,
): ApiResponse<GetConfigHistoryPayload> {
  if (!isSuccess(response)) {
    return response as ApiFailure;
  }

  return {
    ...response,
    data: {
      configHistory:
        response.data.configHistory?.map(normalizeConfigSnapshot) ?? [],
    },
  };
}

function normalizeRollbackResponse(
  response: ApiResponse<RollbackConfigResponse>,
): ApiResponse<ConfigSnapshot> {
  if (!isSuccess(response)) {
    return response;
  }

  return {
    ...response,
    data: normalizeConfigSnapshot(response.data),
  };
}

export const configApi = createApi({
  reducerPath: "configApi",
  baseQuery: baseQueryWithReauth,
  tagTypes: ["ConfigSnapshot"],
  endpoints: (builder) => ({
    exportConfig: builder.query<ApiResponse<ConfigSnapshot>, void>({
      query: () => ({
        url: "/config/export",
        method: "GET",
      }),
      providesTags: [{ type: "ConfigSnapshot", id: "ACTIVE" }],
    }),

    importConfig: builder.mutation<ApiResponse<ConfigSnapshot>, ConfigSnapshot>(
      {
        query: (config) => ({
          url: "/config/import",
          method: "POST",
          body: config,
        }),
        invalidatesTags: [
          { type: "ConfigSnapshot", id: "ACTIVE" },
          { type: "ConfigSnapshot", id: "LIST" },
        ],
      },
    ),

    getConfigHistory: builder.query<ApiResponse<GetConfigHistoryPayload>, void>(
      {
        query: () => ({
          url: "/config/history",
          method: "GET",
        }),
        transformResponse: normalizeConfigHistoryResponse,
        providesTags: [{ type: "ConfigSnapshot", id: "LIST" }],
      },
    ),

    applyConfig: builder.mutation<ApiResponse<ConfigSnapshot>, ApplyConfigBody>({
      query: (body) => ({
        url: "/config/apply",
        method: "POST",
        body,
      }),
      invalidatesTags: [
        { type: "ConfigSnapshot", id: "ACTIVE" },
        { type: "ConfigSnapshot", id: "LIST" },
      ],
    }),

    rollbackConfig: builder.mutation<ApiResponse<ConfigSnapshot>, string>({
      query: (id) => ({
        url: `/config/rollback/${id}`,
        method: "POST",
      }),
      transformResponse: normalizeRollbackResponse,
      async onQueryStarted(_id, { dispatch, queryFulfilled }) {
        const { data } = await queryFulfilled;

        if (!isSuccess(data)) {
          return;
        }

        dispatch(
          configApi.util.updateQueryData("exportConfig", undefined, () => data),
        );
      },
      invalidatesTags: [{ type: "ConfigSnapshot", id: "LIST" }],
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
  useRollbackConfigMutation,
  useGetConfigHistoryQuery,
  useGetConfigDiffQuery,
} = configApi;
