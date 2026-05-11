import { createSlice } from "@reduxjs/toolkit/react";
import type { LoginData } from "../types/authApi/LoginData";

const initialState: LoginData = {
  username: "",
  password: "",
};

const loginDataSlice = createSlice({
  name: "loginData",
  initialState,
  reducers: {
    setLoginData: (state, action) => {
      state.username = action.payload.username;
      state.password = action.payload.password;
    },

    clearLoginData: (state) => {
      state.username = "";
      state.password = "";
    },
  },
});

export const { setLoginData, clearLoginData } = loginDataSlice.actions;
export default loginDataSlice.reducer;
