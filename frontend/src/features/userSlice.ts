import { createSlice } from "@reduxjs/toolkit/react";
import type { LoginResponse } from "../types/authApi/LoginResponse";

const initialState: LoginResponse = {
  id: "",
  username: "",
  createdAt: "",
  accessToken: "",
};

const userSlice = createSlice({
  name: "user",
  initialState,
  reducers: {
    setUser: (state, action) => {
      //localStorage.setItem("token", action.payload.replace(/"/g, ""));
      state.id = action.payload.id;
      state.username = action.payload.username;
      state.createdAt = action.payload.createdAt;
      state.accessToken = action.payload;
    },

    clearUser: (state) => {
      state.id = "";
      state.username = "";
      state.createdAt = "";
      state.accessToken = "";
    },
  },
});

export const { setUser, clearUser } = userSlice.actions;
export default userSlice.reducer;
