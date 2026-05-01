import { createSlice, type PayloadAction } from "@reduxjs/toolkit";
import type { ConfigSnapshot } from "../types/config/Config";

type ConfigState = {
  config: ConfigSnapshot;
  configHistory: ConfigSnapshot[];
  selectedSnapshotId: string;
};

const initialState: ConfigState = {
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
  configHistory: [],
  selectedSnapshotId: "",
};

export const configSlice = createSlice({
  name: "config",
  initialState,
  reducers: {
    setConfig: (state, action: PayloadAction<{ config: ConfigSnapshot }>) => {
      state.config = action.payload.config;
    },
    setConfigHistory: (
      state,
      action: PayloadAction<{ configHistory: ConfigSnapshot[] }>,
    ) => {
      state.configHistory = action.payload.configHistory;

      if (
        state.selectedSnapshotId &&
        action.payload.configHistory.some(
          (snapshot) => snapshot.id === state.selectedSnapshotId,
        )
      ) {
        return;
      }

      state.selectedSnapshotId =
        action.payload.configHistory.find((snapshot) => snapshot.isActive)?.id ??
        action.payload.configHistory[0]?.id ??
        "";
    },
    setSelectedSnapshotId: (state, action: PayloadAction<string>) => {
      state.selectedSnapshotId = action.payload;
    },
  },
});

export const { setConfig, setConfigHistory, setSelectedSnapshotId } =
  configSlice.actions;
export default configSlice.reducer;
