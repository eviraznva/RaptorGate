import { createSlice, type PayloadAction } from "@reduxjs/toolkit/react";
import type { NatRulesPayload } from "../services/natRules";
import type { NatRule } from "../types/nat/NatRule";

const initialState: NatRulesPayload = {
  natRules: [],
};

export const natRulesSlice = createSlice({
  name: "natRules",
  initialState,
  reducers: {
    setNatRules: (state, action: PayloadAction<NatRule[]>) => {
      state.natRules = action.payload;
    },

    addNatRule: (state, action: PayloadAction<NatRule>) => {
      state.natRules.push(action.payload);
    },

    editNatRule: (state, action: PayloadAction<NatRule>) => {
      const natRuleIndex = state.natRules.findIndex(
        (rule) => rule.id === action.payload.id,
      );

      state.natRules = state.natRules.map((rule, index) => {
        if (index === natRuleIndex) return action.payload;
        else return rule;
      });
    },

    deleteNatRule: (state, action: PayloadAction<string>) => {
      state.natRules = state.natRules.filter((rule) => rule.id !== action.payload);
    },
  },
});

export const { setNatRules, addNatRule, editNatRule, deleteNatRule } = natRulesSlice.actions;
export default natRulesSlice.reducer;
