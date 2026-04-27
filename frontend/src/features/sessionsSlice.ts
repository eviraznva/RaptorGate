import { createSlice, type PayloadAction } from "@reduxjs/toolkit/react";
import type { TcpSessionsPayload } from "../services/sessions";
import type { TcpTrackedSession } from "../types/sessions/TcpSession";

const initialState: TcpSessionsPayload = {
  tcpSessions: [],
};

export const sessionsSlice = createSlice({
  name: "sessions",
  initialState,
  reducers: {
    setTcpSessions: (state, action: PayloadAction<TcpTrackedSession[]>) => {
      state.tcpSessions = action.payload;
    },
  },
});

export const { setTcpSessions } = sessionsSlice.actions;
export default sessionsSlice.reducer;
