import { createSlice, type PayloadAction } from "@reduxjs/toolkit";
import {
  defaultIpsConfig,
  type IpsAppProtocol,
  type IpsConfig,
  type IpsConfigState,
  type IpsDetectionConfig,
  type IpsGeneralConfig,
  type IpsSignatureConfig,
  type IpsTabKey,
} from "../types/ipsConfig/IpsConfig";

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function makeNewSignature(index: number): IpsSignatureConfig {
  const id = `sig-${Date.now()}-${index}`;

  return {
    id,
    name: `New Signature ${index + 1}`,
    enabled: true,
    category: "other",
    pattern: "",
    matchType: "regex",
    patternEncoding: "text",
    caseInsensitive: false,
    severity: "low",
    action: "alert",
    appProtocols: [],
    srcPorts: [],
    dstPorts: [],
  };
}

function firstSignatureId(config: IpsConfig): string | null {
  return config.signatures.length > 0 ? config.signatures[0].id : null;
}

const initialState: IpsConfigState = {
  activeTab: "general",
  draftConfig: deepClone(defaultIpsConfig),
  appliedConfig: deepClone(defaultIpsConfig),
  selectedSignatureId: null,
};

const ipsConfigSlice = createSlice({
  name: "ipsConfig",
  initialState,
  reducers: {
    setIpsActiveTab: (state, action: PayloadAction<IpsTabKey>) => {
      state.activeTab = action.payload;
    },

    setIpsGeneralConfig: (
      state,
      action: PayloadAction<Partial<IpsGeneralConfig>>,
    ) => {
      state.draftConfig.general = {
        ...state.draftConfig.general,
        ...action.payload,
      };
    },

    setIpsDetectionConfig: (
      state,
      action: PayloadAction<Partial<IpsDetectionConfig>>,
    ) => {
      state.draftConfig.detection = {
        ...state.draftConfig.detection,
        ...action.payload,
      };
    },

    selectIpsSignature: (state, action: PayloadAction<string | null>) => {
      state.selectedSignatureId = action.payload;
    },

    addIpsSignature: (state) => {
      const signature = makeNewSignature(state.draftConfig.signatures.length);
      state.draftConfig.signatures.push(signature);
      state.selectedSignatureId = signature.id;
    },

    removeIpsSignature: (state, action: PayloadAction<string>) => {
      state.draftConfig.signatures = state.draftConfig.signatures.filter(
        (signature) => signature.id !== action.payload,
      );

      if (state.selectedSignatureId === action.payload) {
        state.selectedSignatureId = firstSignatureId(state.draftConfig);
      }
    },

    updateSelectedIpsSignature: (
      state,
      action: PayloadAction<Partial<IpsSignatureConfig>>,
    ) => {
      if (!state.selectedSignatureId) {
        return;
      }

      state.draftConfig.signatures = state.draftConfig.signatures.map(
        (signature) => {
          if (signature.id !== state.selectedSignatureId) {
            return signature;
          }

          return {
            ...signature,
            ...action.payload,
          };
        },
      );

      if (action.payload.id) {
        state.selectedSignatureId = action.payload.id;
      }
    },

    setSelectedIpsSignatureProtocols: (
      state,
      action: PayloadAction<IpsAppProtocol[]>,
    ) => {
      if (!state.selectedSignatureId) {
        return;
      }

      state.draftConfig.signatures = state.draftConfig.signatures.map(
        (signature) =>
          signature.id === state.selectedSignatureId
            ? { ...signature, appProtocols: action.payload }
            : signature,
      );
    },

    setSelectedIpsSignatureSrcPorts: (state, action: PayloadAction<number[]>) => {
      if (!state.selectedSignatureId) {
        return;
      }

      state.draftConfig.signatures = state.draftConfig.signatures.map(
        (signature) =>
          signature.id === state.selectedSignatureId
            ? { ...signature, srcPorts: action.payload }
            : signature,
      );
    },

    setSelectedIpsSignatureDstPorts: (state, action: PayloadAction<number[]>) => {
      if (!state.selectedSignatureId) {
        return;
      }

      state.draftConfig.signatures = state.draftConfig.signatures.map(
        (signature) =>
          signature.id === state.selectedSignatureId
            ? { ...signature, dstPorts: action.payload }
            : signature,
      );
    },

    setIpsSignatures: (state, action: PayloadAction<IpsSignatureConfig[]>) => {
      state.draftConfig.signatures = action.payload;
      if (
        state.selectedSignatureId &&
        !action.payload.some((s) => s.id === state.selectedSignatureId)
      ) {
        state.selectedSignatureId = action.payload.length > 0 ? action.payload[0].id : null;
      }
    },

    applyIpsDraft: (state) => {
      state.appliedConfig = deepClone(state.draftConfig);
    },

    resetIpsAll: (state) => {
      state.draftConfig = deepClone(state.appliedConfig);

      if (
        state.selectedSignatureId &&
        !state.draftConfig.signatures.some(
          (signature) => signature.id === state.selectedSignatureId,
        )
      ) {
        state.selectedSignatureId = firstSignatureId(state.draftConfig);
      }
    },

    resetIpsTab: (state) => {
      if (state.activeTab === "general") {
        state.draftConfig.general = deepClone(state.appliedConfig.general);
        return;
      }

      if (state.activeTab === "detection") {
        state.draftConfig.detection = deepClone(state.appliedConfig.detection);
        return;
      }

      state.draftConfig.signatures = deepClone(state.appliedConfig.signatures);

      if (
        state.selectedSignatureId &&
        !state.draftConfig.signatures.some(
          (signature) => signature.id === state.selectedSignatureId,
        )
      ) {
        state.selectedSignatureId = firstSignatureId(state.draftConfig);
      }
    },
  },
});

export const {
  setIpsActiveTab,
  setIpsGeneralConfig,
  setIpsDetectionConfig,
  setIpsSignatures,
  selectIpsSignature,
  addIpsSignature,
  removeIpsSignature,
  updateSelectedIpsSignature,
  setSelectedIpsSignatureProtocols,
  setSelectedIpsSignatureSrcPorts,
  setSelectedIpsSignatureDstPorts,
  applyIpsDraft,
  resetIpsAll,
  resetIpsTab,
} = ipsConfigSlice.actions;

export default ipsConfigSlice.reducer;
