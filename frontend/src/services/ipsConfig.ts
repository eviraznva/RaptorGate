import { createApi } from "@reduxjs/toolkit/query/react";
import { baseQueryWithReauth } from "./baseQueryWithReauth";
import type { ApiResponse } from "../types/ApiResponse";
import type { IpsConfig } from "../types";

export type IpsConfigPayload = {
  ipsConfig: IpsConfig;
};

export const ipsConfigApi = createApi({
  reducerPath: "ipsConfigApi",
  baseQuery: baseQueryWithReauth,
  tagTypes: ["IpsConfig"],
  endpoints: (builder) => ({
    getIpsConfig: builder.query<ApiResponse<IpsConfigPayload>, void>({
      query: () => ({
        url: "/ips-config",
        method: "GET",
      }),
      providesTags: ["IpsConfig"],
    }),

    updateIpsConfig: builder.mutation<ApiResponse<IpsConfigPayload>, IpsConfig>(
      {
        query: (ipsConfig) => ({
          url: "/ips-config",
          method: "PUT",
          body: ipsConfig,
        }),
        invalidatesTags: ["IpsConfig"],
      },
    ),
  }),
});

export const { useGetIpsConfigQuery, useUpdateIpsConfigMutation } =
  ipsConfigApi;
