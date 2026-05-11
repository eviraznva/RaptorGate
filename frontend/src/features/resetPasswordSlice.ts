import { createSlice } from "@reduxjs/toolkit/react";
import type { ResetPasswordData } from "../types/authApi/ResetPasswotdData";

const initialState: ResetPasswordData = {
  username: "",
  recoveryToken: "",
  newPassword: "",
};

const resetPasswordSlice = createSlice({
  name: "resetPassword",
  initialState,
  reducers: {
    setUsername: (state, action) => {
      state.username = action.payload;
    },

    setRecoveryToken: (state, action) => {
      state.recoveryToken = action.payload;
    },

    setNewPassword: (state, action) => {
      state.newPassword = action.payload;
    },
  },
});

export const { setUsername, setRecoveryToken, setNewPassword } =
  resetPasswordSlice.actions;
export default resetPasswordSlice.reducer;
