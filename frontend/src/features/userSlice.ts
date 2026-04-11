import { createSlice, type PayloadAction } from "@reduxjs/toolkit/react";
import type { LoginResponse } from "../types/authApi/LoginResponse";

const storedUser =
  localStorage.getItem("user") === null
    ? {
        id: "",
        username: "",
        createdAt: "",
        accessToken: "",
      }
    : (JSON.parse(localStorage.getItem("user") as string) as LoginResponse);

const initialState: LoginResponse = storedUser;

const userSlice = createSlice({
  name: "user",
  initialState,
  reducers: {
    setUser: (state, action: PayloadAction<LoginResponse>) => {
      localStorage.setItem("user", JSON.stringify(action.payload));
      state.id = action.payload.id;
      state.username = action.payload.username;
      state.createdAt = action.payload.createdAt;
      state.accessToken = action.payload.accessToken;
    },

    clearUser: (state) => {
      state.id = "";
      state.username = "";
      state.createdAt = "";
      state.accessToken = "";
      localStorage.removeItem("user");
    },
  },
});

export const { setUser, clearUser } = userSlice.actions;
export default userSlice.reducer;
