import { createApi } from "@reduxjs/toolkit/query/react";
import type { NatRule } from "../types/nat/NatRule";
import { baseQueryWithReauth } from "./baseQueryWithReauth";
import type { ApiResponse } from "../types/ApiResponse";

export type NatRulesPayload = {
  natRules: NatRule[];
};

export type CreateNatRuleBody = {
  type: string;
  isActive: boolean;
  sourceIp?: string | null;
  destinationIp?: string | null;
  sourcePort?: number | null;
  destinationPort?: number | null;
  translatedIp?: string | null;
  translatedPort?: number | null;
  priority: number;
};

export const natRulesApi = createApi({
  reducerPath: "natRulesApi",
  baseQuery: baseQueryWithReauth,
  endpoints: (builder) => ({
    getNatRules: builder.query<ApiResponse<NatRulesPayload>, void>({
      query: () => ({
        url: "/nat",
        method: "GET",
      }),
    }),

    createNatRule: builder.mutation<
      ApiResponse<{ natRule: NatRule }>,
      CreateNatRuleBody
    >({
      query: (body) => ({
        url: "/nat",
        method: "POST",
        body,
      }),
    }),

    updateNatRule: builder.mutation<
      ApiResponse<{ natRule: NatRule }>,
      { id: string } & Partial<CreateNatRuleBody>
    >({
      query: ({ id, ...body }) => ({
        url: `/nat/${id}`,
        method: "PUT",
        body,
      }),
    }),

    deleteNatRule: builder.mutation<void, string>({
      query: (id) => ({
        url: `/nat/${id}`,
        method: "DELETE",
      }),
    }),
  }),
});

export const {
  useGetNatRulesQuery,
  useCreateNatRuleMutation,
  useUpdateNatRuleMutation,
  useDeleteNatRuleMutation,
} = natRulesApi;
