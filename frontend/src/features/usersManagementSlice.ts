import { createSlice, type PayloadAction } from "@reduxjs/toolkit/react";
import type { UsersPayload } from "../services/users";
import type { DashboardUser } from "../types/users/User";

const initialState: UsersPayload = {
  users: [],
};

export const usersManagementSlice = createSlice({
  name: "usersManagement",
  initialState,
  reducers: {
    setUsers: (state, action: PayloadAction<DashboardUser[]>) => {
      state.users = action.payload;
    },

    addUser: (state, action: PayloadAction<DashboardUser>) => {
      state.users.push(action.payload);
    },

    editUser: (state, action: PayloadAction<DashboardUser>) => {
      const userIndex = state.users.findIndex(
        (user) => user.id === action.payload.id,
      );

      state.users = state.users.map((user, index) => {
        if (index === userIndex) return action.payload;
        else return user;
      });
    },

    deleteUser: (state, action: PayloadAction<string>) => {
      state.users = state.users.filter((user) => user.id !== action.payload);
    },
  },
});

export const { setUsers, addUser, editUser, deleteUser } =
  usersManagementSlice.actions;
export default usersManagementSlice.reducer;
