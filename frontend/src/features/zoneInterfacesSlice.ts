import { createSlice, type PayloadAction } from "@reduxjs/toolkit/react";
import type { ZoneInterfacesPayload } from "../services/zoneInterfaces";
import type { ZoneInterface } from "../types/zones/ZoneInterface";

const initialState: ZoneInterfacesPayload = {
  zoneInterfaces: [],
};

export const zoneInterfacesSlice = createSlice({
  name: "zoneInterfaces",
  initialState,
  reducers: {
    setZoneInterfaces: (state, action: PayloadAction<ZoneInterface[]>) => {
      state.zoneInterfaces = action.payload;
    },
    editZoneInterface: (state, action: PayloadAction<ZoneInterface>) => {
      const idx = state.zoneInterfaces.findIndex(
        (zi) => zi.id === action.payload.id,
      );
      if (idx !== -1) state.zoneInterfaces[idx] = action.payload;
    },
  },
});

export const { setZoneInterfaces, editZoneInterface } =
  zoneInterfacesSlice.actions;
export default zoneInterfacesSlice.reducer;
