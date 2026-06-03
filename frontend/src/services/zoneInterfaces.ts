import { createApi } from "@reduxjs/toolkit/query/react";
import type { ApiResponse } from "../types/ApiResponse";
import type { ZoneInterface } from "../types/zones/ZoneInterface";
import { baseQueryWithReauth } from "./baseQueryWithReauth";

export type ZoneInterfacesPayload = {
  zoneInterfaces: ZoneInterface[];
};

export type EditZoneInterfaceBody = {
  zoneId: string;
  vlanId: number | null;
  parentInterfaceId?: string | null;
  ipv4Address: string | null;
  ipv4Mask: number | null;
  ipv6Address: string | null;
  ipv6Mask: number | null;
  isActive: boolean;
  sniffed: boolean;
};

export type CreateZoneInterfaceBody = {
  parentInterfaceId: string;
  vlanId: number;
  zoneId: string;
  ipv4Address: string | null;
  ipv4Mask: number | null;
  ipv6Address: string | null;
  ipv6Mask: number | null;
  isActive?: boolean;
  sniffed?: boolean;
};

export const zoneInterfacesApi = createApi({
  reducerPath: "zoneInterfacesApi",
  baseQuery: baseQueryWithReauth,
  tagTypes: ["ZoneInterfaces"],
  endpoints: (builder) => ({
    getZoneInterfaces: builder.query<ApiResponse<ZoneInterfacesPayload>, void>({
      query: () => ({
        url: "/zone-interface",
        method: "GET",
      }),
      providesTags: ["ZoneInterfaces"],
    }),
    editZoneInterface: builder.mutation<
      ApiResponse<{ zoneInterface: ZoneInterface }>,
      { id: string } & EditZoneInterfaceBody
    >({
      query: ({ id, ...body }) => ({
        url: `/zone-interface/${id}`,
        method: "PUT",
        body,
      }),
      invalidatesTags: ["ZoneInterfaces"],
    }),
    createZoneInterface: builder.mutation<
      ApiResponse<{ zoneInterface: ZoneInterface }>,
      CreateZoneInterfaceBody
    >({
      query: (body) => ({
        url: "/zone-interface",
        method: "POST",
        body,
      }),
      invalidatesTags: ["ZoneInterfaces"],
    }),
    deleteZoneInterface: builder.mutation<void, string>({
      query: (id) => ({
        url: `/zone-interface/${id}`,
        method: "DELETE",
      }),
      invalidatesTags: ["ZoneInterfaces"],
    }),
  }),
});

export const {
  useGetZoneInterfacesQuery,
  useEditZoneInterfaceMutation,
  useCreateZoneInterfaceMutation,
  useDeleteZoneInterfaceMutation,
} = zoneInterfacesApi;
