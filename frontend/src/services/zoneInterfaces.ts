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
  ipv4Address: string | null;
  ipv4Mask: number | null;
  ipv6Address: string | null;
  ipv6Mask: number | null;
  isActive: boolean;
};

export const zoneInterfacesApi = createApi({
  reducerPath: "zoneInterfacesApi",
  baseQuery: baseQueryWithReauth,
  endpoints: (builder) => ({
    getZoneInterfaces: builder.query<ApiResponse<ZoneInterfacesPayload>, void>({
      query: () => ({
        url: "/zone-interface",
        method: "GET",
      }),
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
    }),
  }),
});

export const { useGetZoneInterfacesQuery, useEditZoneInterfaceMutation } =
  zoneInterfacesApi;
