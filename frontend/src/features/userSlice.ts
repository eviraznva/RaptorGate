import { createSlice, type PayloadAction } from "@reduxjs/toolkit/react";
import type { LoginResponse } from "../types/authApi/LoginResponse";

const storedUser =
  localStorage.getItem("user") === null
    ? {
        id: "",
        username: "",
        createdAt: "",
        recoveryToken: null,
        isFirstLogin: false,
        showRecoveryToken: false,
        accessToken: "",
        roles: [],
        authProvider: undefined,
        authProfileId: undefined,
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
      state.recoveryToken = action.payload.recoveryToken;
      state.isFirstLogin = action.payload.isFirstLogin;
      state.showRecoveryToken = action.payload.showRecoveryToken;
      state.accessToken = action.payload.accessToken;
      state.roles = action.payload.roles ?? [];
      state.authProvider = action.payload.authProvider;
      state.authProfileId = action.payload.authProfileId;
    },

    clearUser: (state) => {
      state.id = "";
      state.username = "";
      state.createdAt = "";
      state.recoveryToken = null;
      state.isFirstLogin = false;
      state.showRecoveryToken = false;
      state.accessToken = "";
      state.roles = [];
      state.authProvider = undefined;
      state.authProfileId = undefined;
      localStorage.removeItem("user");
    },

    updateAccessToken: (state, action: PayloadAction<string>) => {
      state.accessToken = action.payload;
      localStorage.setItem("user", JSON.stringify(state));
    },

    clearRecoveryToken: (state) => {
      state.recoveryToken = null;
      state.showRecoveryToken = false;
      localStorage.setItem("user", JSON.stringify(state));
    },

    setIsFirstLogin: (state, action: PayloadAction<boolean>) => {
      state.isFirstLogin = action.payload;
      localStorage.setItem("user", JSON.stringify(state));
    },
  },
});

export const {
  setUser,
  clearUser,
  updateAccessToken,
  clearRecoveryToken,
  setIsFirstLogin,
} = userSlice.actions;
export default userSlice.reducer;
