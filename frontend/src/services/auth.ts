import { createApi } from "@reduxjs/toolkit/query/react";
import type { ApiResponse } from "../types/ApiResponse";
import type { LoginResponse } from "../types";
import type { LoginData } from "../types/authApi/LoginData";
import type { RefreshTokenData } from "../types/authApi/RefreshTokenData";
import type { RefreshTokenResponse } from "../types/authApi/RefreshTokenResponse";
import type { LogoutData } from "../types/authApi/LogoutData";
import { baseQueryWithReauth } from "./baseQueryWithReauth";
import type { ResetPasswordData } from "../types/authApi/ResetPasswotdData";

export const authApi = createApi({
  reducerPath: "authApi",
  baseQuery: baseQueryWithReauth,
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

    resetPassword: builder.mutation<ApiResponse<void>, ResetPasswordData>({
      query: (resetPasswordData) => ({
        url: "/auth/recover-password",
        method: "POST",
        body: resetPasswordData,
      }),
    }),
  }),
});

export const {
  useLoginMutation,
  useRefreshTokenMutation,
  useLogoutMutation,
  useResetPasswordMutation,
} = authApi;
