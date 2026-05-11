import { createSlice, type PayloadAction } from "@reduxjs/toolkit/react";
import type { ZonesPayload } from "../services/zones";
import type { Zone } from "../types/zones/Zone";

const initialState: ZonesPayload = {
  zones: [],
};

export const zonesSlice = createSlice({
  name: "zones",
  initialState,
  reducers: {
    setZones: (state, action: PayloadAction<Zone[]>) => {
      state.zones = action.payload;
    },

    addZone: (state, action: PayloadAction<Zone>) => {
      state.zones.push(action.payload);
    },

    editZone: (state, action: PayloadAction<Zone>) => {
      const zoneIndex = state.zones.findIndex(
        (zone) => zone.id === action.payload.id,
      );

      state.zones = state.zones.map((zone, index) => {
        if (index === zoneIndex) return action.payload;
        else return zone;
      });
    },

    deleteZone: (state, action: PayloadAction<string>) => {
      state.zones = state.zones.filter((zone) => zone.id !== action.payload);
    },
  },
});

export const { setZones, addZone, editZone, deleteZone } = zonesSlice.actions;
export default zonesSlice.reducer;
