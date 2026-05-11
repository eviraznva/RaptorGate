import { createSlice, type PayloadAction } from "@reduxjs/toolkit/react";
import type { ZonePairsPayload } from "../services/zonePairs";
import type { ZonePair } from "../types/zones/ZonePair";

const initialState: ZonePairsPayload = {
  zonePairs: [],
};

export const zonePairsSlice = createSlice({
  name: "zonePairs",
  initialState,
  reducers: {
    setZonePairs: (state, action: PayloadAction<ZonePair[]>) => {
      state.zonePairs = action.payload;
    },

    addZonePair: (state, action: PayloadAction<ZonePair>) => {
      state.zonePairs.push(action.payload);
    },

    editZonePair: (state, action: PayloadAction<ZonePair>) => {
      const zonePairIndex = state.zonePairs.findIndex(
        (zonePair) => zonePair.id === action.payload.id,
      );

      state.zonePairs = state.zonePairs.map((zonePair, index) => {
        if (index === zonePairIndex) return action.payload;
        else return zonePair;
      });
    },

    deleteZonePair: (state, action: PayloadAction<string>) => {
      state.zonePairs = state.zonePairs.filter((zonePair) => zonePair.id !== action.payload);
    },
  },
});

export const { setZonePairs, addZonePair, editZonePair, deleteZonePair } = zonePairsSlice.actions;
export default zonePairsSlice.reducer;
