import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";
import type { ApiFailure, ApiResponse } from "../types/ApiResponse";
import type { LoginResponse } from "../types";
import type { LoginData } from "../types/authApi/LoginData";
import type { RefreshTokenData } from "../types/authApi/RefreshTokenData";
import type { RefreshTokenResponse } from "../types/authApi/RefreshTokenResponse";
import type { LogoutData } from "../types/authApi/LogoutData";

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
    refreshToken: builder.mutation<
      ApiResponse<RefreshTokenResponse>,
      RefreshTokenData
    >({
      query: (RefreshTokenData) => ({
        url: "/auth/refresh",
        method: "POST",
        headers: {
          Authorization: `Bearer ${RefreshTokenData.accessToken}`,
        },
      }),
    }),
    logout: builder.mutation<ApiResponse<void>, LogoutData>({
      query: (logoutData) => ({
        url: "/auth/logout",
        method: "POST",
        headers: {
          Authorization: `Bearer ${logoutData.accessToken}`,
        },
      }),
    }),
  }),
});

export const { useLoginMutation, useRefreshTokenMutation, useLogoutMutation } =
  authApi;
