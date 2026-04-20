import { createApi } from "@reduxjs/toolkit/query/react";
import type { Zone } from "../types/zones/Zone";
import { baseQueryWithReauth } from "./baseQueryWithReauth";
import type { ApiResponse } from "../types/ApiResponse";

export type ZonesPayload = {
  zones: Zone[];
};

export type CreateZoneBody = {
  name: string;
  description: string;
  isActive: boolean;
};

export const zonesApi = createApi({
  reducerPath: "zonesApi",
  baseQuery: baseQueryWithReauth,
  endpoints: (builder) => ({
    getZones: builder.query<ApiResponse<ZonesPayload>, void>({
      query: () => ({
        url: "/zones",
        method: "GET",
      }),
    }),

    createZone: builder.mutation<ApiResponse<{ zone: Zone }>, CreateZoneBody>({
      query: (body) => ({
        url: "/zones",
        method: "POST",
        body,
      }),
    }),

    updateZone: builder.mutation<
      ApiResponse<{ zone: Zone }>,
      { id: string } & Partial<CreateZoneBody>
    >({
      query: ({ id, ...body }) => ({
        url: `/zones/${id}`,
        method: "PUT",
        body,
      }),
    }),

    deleteZone: builder.mutation<void, string>({
      query: (id) => ({
        url: `/zones/${id}`,
        method: "DELETE",
      }),
    }),
  }),
});

export const {
  useGetZonesQuery,
  useCreateZoneMutation,
  useUpdateZoneMutation,
  useDeleteZoneMutation,
} = zonesApi;
