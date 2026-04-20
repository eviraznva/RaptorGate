import { createApi } from "@reduxjs/toolkit/query/react";
import { baseQueryWithReauth } from "./baseQueryWithReauth";
import type { ApiResponse } from "../types/ApiResponse";
import type { Rule } from "../types/rules/Rules";

export type RulesPayload = {
  rules: Rule[];
};

export type CreateRuleBody = {
  name: string;
  description?: string;
  zonePairId: string;
  isActive: boolean;
  content: string;
  priority: number;
};

export type UpdateRuleBody = Partial<CreateRuleBody>;

export const rulesApi = createApi({
  reducerPath: "rulesApi",
  baseQuery: baseQueryWithReauth,
  endpoints: (builder) => ({
    getRules: builder.query<ApiResponse<RulesPayload>, void>({
      query: () => ({ url: "/rule", method: "GET" }),
    }),

    createRule: builder.mutation<ApiResponse<{ rule: Rule }>, CreateRuleBody>({
      query: (body) => ({ url: "/rule", method: "POST", body }),
    }),

    updateRule: builder.mutation<
      ApiResponse<Rule>,
      { id: string } & UpdateRuleBody
    >({
      query: ({ id, ...body }) => ({ url: `/rule/${id}`, method: "PUT", body }),
    }),

    deleteRule: builder.mutation<void, string>({
      query: (id) => ({ url: `/rule/${id}`, method: "DELETE" }),
    }),
  }),
});

export const {
  useGetRulesQuery,
  useCreateRuleMutation,
  useUpdateRuleMutation,
  useDeleteRuleMutation,
} = rulesApi;
