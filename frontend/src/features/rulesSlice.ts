import { createSlice, type PayloadAction } from "@reduxjs/toolkit/react";
import type { RulesPayload } from "../services/rules";
import type { Rule } from "../types/rules/Rules";

const initialState: RulesPayload = {
  rules: [],
};

export const rulesSlice = createSlice({
  name: "rules",
  initialState,
  reducers: {
    setRules: (state, action: PayloadAction<Rule[]>) => {
      state.rules = action.payload;
    },

    addRule: (state, action: PayloadAction<Rule>) => {
      state.rules.push(action.payload);
    },

    editRule: (state, action: PayloadAction<Rule>) => {
      const ruleIndex = state.rules.findIndex(
        (rule) => rule.id === action.payload.id,
      );

      state.rules = state.rules.map((rule, index) => {
        if (index === ruleIndex) return action.payload;
        else return rule;
      });
    },

    deleteRule: (state, action: PayloadAction<string>) => {
      state.rules = state.rules.filter((rule) => rule.id !== action.payload);
    },
  },
});

export const { setRules, addRule, editRule, deleteRule } = rulesSlice.actions;
export default rulesSlice.reducer;
