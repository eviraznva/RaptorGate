import { createSlice } from "@reduxjs/toolkit/react";
import type { ConfigSnapshot } from "../types/config/Config";

const initialState: { config: ConfigSnapshot } = {
  config: {
    id: "",
    versionNumber: 0,
    snapshotType: "manual_import",
    checksum: "",
    isActive: false,
    payloadJson: {},
    changeSummary: null,
    createdAt: "",
    createdBy: "",
  },
};

export const configSlice = createSlice({
  name: "config",
  initialState,
  reducers: {
    setConfig: (state, action) => {
      state.config = action.payload.config;
    },
  },
});

export const { setConfig } = configSlice.actions;
export default configSlice.reducer;
