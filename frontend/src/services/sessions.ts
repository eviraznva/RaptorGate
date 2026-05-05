import { createApi } from "@reduxjs/toolkit/query/react";
import type { ApiResponse } from "../types/ApiResponse";
import type { TcpTrackedSession } from "../types/sessions/TcpSession";
import { baseQueryWithReauth } from "./baseQueryWithReauth";

export type TcpSessionsPayload = {
  tcpSessions: TcpTrackedSession[];
};

export const sessionsApi = createApi({
  reducerPath: "sessionsApi",
  baseQuery: baseQueryWithReauth,
  endpoints: (builder) => ({
    getTcpSessions: builder.query<ApiResponse<TcpSessionsPayload>, void>({
      query: () => ({
        url: "/tcp-sessions",
        method: "GET",
      }),
    }),
  }),
});

export const { useGetTcpSessionsQuery } = sessionsApi;
