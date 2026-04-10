import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";
import type { ApiFailure, ApiResponse } from "../types/ApiResponse";
import type { LoginResponse } from "../types";
import type { LoginData } from "../types/authApi/LoginData";

const baseQuery = fetchBaseQuery({
  baseUrl: `${import.meta.env.RAPTOR_GATE_API_URL}`,
  credentials: "include",
  mode: "cors",
});

const customBaseQuery = async (args: any, api: any, extraOptions: any) => {
  const result = await baseQuery(args, api, extraOptions);
  if (result.error) return { error: result.error.data as ApiFailure };

  return result;
};

export const authApi = createApi({
  reducerPath: "authApi",
  baseQuery: customBaseQuery,
  endpoints: (builder) => ({
    login: builder.mutation<ApiResponse<LoginResponse>, LoginData>({
      query: (loginData) => ({
        url: "/auth/login",
        method: "POST",
        body: loginData,
      }),
    }),
  }),
});

export const { useLoginMutation } = authApi;
