import { createSlice } from "@reduxjs/toolkit/react";
import type { ConfigDiffChangeType } from "../types/config/ConfigDiff";

type ConfigDiffTypeFilter = 'all' | ConfigDiffChangeType;

interface ConfigDiffState {
  baseId: string;
  targetId: string;
  selectedChangeIndex: number;
  typeFilter: ConfigDiffTypeFilter;
  sectionFilter: string;
  search: string;
}

const initialState: ConfigDiffState = {
  baseId: '',
  targetId: '',
  selectedChangeIndex: 0,
  typeFilter: 'all',
  sectionFilter: 'all',
  search: '',
};

export const configDiffSlice = createSlice({
  name: 'configDiff',
  initialState,
  reducers: {
    setBaseId: (state, action: { payload: string }) => {
      state.baseId = action.payload;
      state.selectedChangeIndex = 0;
    },
    setTargetId: (state, action: { payload: string }) => {
      state.targetId = action.payload;
      state.selectedChangeIndex = 0;
    },
    setTypeFilter: (state, action: { payload: ConfigDiffTypeFilter }) => {
      state.typeFilter = action.payload;
      state.selectedChangeIndex = 0;
    },
    setSectionFilter: (state, action: { payload: string }) => {
      state.sectionFilter = action.payload;
      state.selectedChangeIndex = 0;
    },
    setSearch: (state, action: { payload: string }) => {
      state.search = action.payload;
      state.selectedChangeIndex = 0;
    },
    setSelectedChangeIndex: (state, action: { payload: number }) => {
      state.selectedChangeIndex = action.payload;
    },
  },
});

export const {
  setBaseId,
  setTargetId,
  setTypeFilter,
  setSectionFilter,
  setSearch,
  setSelectedChangeIndex,
} = configDiffSlice.actions;

export default configDiffSlice.reducer;
