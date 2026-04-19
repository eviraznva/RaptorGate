import { createApi } from "@reduxjs/toolkit/query/react";
import type { ZonePair } from "../types/zones/ZonePair";
import { baseQueryWithReauth } from "./baseQueryWithReauth";
import type { ApiResponse } from "../types/ApiResponse";

export type ZonePairsPayload = {
  zonePairs: ZonePair[];
};

export type CreateZonePairBody = {
  srcZoneId: string;
  dstZoneId: string;
  defaultPolicy: string;
};

export const zonePairsApi = createApi({
  reducerPath: "zonePairsApi",
  baseQuery: baseQueryWithReauth,
  endpoints: (builder) => ({
    getZonePairs: builder.query<ApiResponse<ZonePairsPayload>, void>({
      query: () => ({
        url: "/zone-pairs",
        method: "GET",
      }),
    }),

    createZonePair: builder.mutation<ApiResponse<{ zonePair: ZonePair }>, CreateZonePairBody>({
      query: (body) => ({
        url: "/zone-pairs",
        method: "POST",
        body,
      }),
    }),

    updateZonePair: builder.mutation<
      ApiResponse<{ zonePair: ZonePair }>,
      { id: string } & Partial<CreateZonePairBody>
    >({
      query: ({ id, ...body }) => ({
        url: `/zone-pairs/${id}`,
        method: "PUT",
        body,
      }),
    }),

    deleteZonePair: builder.mutation<void, string>({
      query: (id) => ({
        url: `/zone-pairs/${id}`,
        method: "DELETE",
      }),
    }),
  }),
});

export const {
  useGetZonePairsQuery,
  useCreateZonePairMutation,
  useUpdateZonePairMutation,
  useDeleteZonePairMutation,
} = zonePairsApi;
