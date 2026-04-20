import { createApi } from "@reduxjs/toolkit/query/react";
import type { DashboardUser } from "../types/users/User";
import { baseQueryWithReauth } from "./baseQueryWithReauth";
import type { ApiResponse } from "../types/ApiResponse";

export type UsersPayload = {
  users: DashboardUser[];
};

export type CreateUserBody = {
  username: string;
  password: string;
  roles: string[];
};

export const usersApi = createApi({
  reducerPath: "usersApi",
  baseQuery: baseQueryWithReauth,
  endpoints: (builder) => ({
    getUsers: builder.query<ApiResponse<UsersPayload>, void>({
      query: () => ({
        url: "/user",
        method: "GET",
      }),
    }),

    createUser: builder.mutation<
      ApiResponse<{ user: DashboardUser }>,
      CreateUserBody
    >({
      query: (body) => ({
        url: "/user",
        method: "POST",
        body,
      }),
    }),

    updateUser: builder.mutation<
      ApiResponse<{ user: DashboardUser }>,
      { id: string } & Partial<CreateUserBody>
    >({
      query: ({ id, ...body }) => ({
        url: `/user/${id}`,
        method: "PUT",
        body,
      }),
    }),

    deleteUser: builder.mutation<void, string>({
      query: (id) => ({
        url: `/user/${id}`,
        method: "DELETE",
      }),
    }),
  }),
});

export const {
  useGetUsersQuery,
  useCreateUserMutation,
  useUpdateUserMutation,
  useDeleteUserMutation,
} = usersApi;
