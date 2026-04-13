import { createSlice, type PayloadAction } from "@reduxjs/toolkit";
import {
  defaultDnsInspectionConfig,
  type DnsInspectionBlocklistConfig,
  type DnsInspectionConfig,
  type DnsInspectionDnsTunnelingConfig,
  type DnsInspectionDnssecCacheConfig,
  type DnsInspectionDnssecCacheTtlConfig,
  type DnsInspectionDnssecConfig,
  type DnsInspectionDnssecResolverConfig,
  type DnsInspectionDnssecResolverEndpoint,
  type DnsInspectionGeneralConfig,
  type DnsInspectionState,
  type DnsTabKey,
} from "../types/dnsInspection/DnsInspectionConfig";

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

const initialState: DnsInspectionState = {
  activeTab: "general",
  draftConfig: deepClone(defaultDnsInspectionConfig),
  appliedConfig: deepClone(defaultDnsInspectionConfig),
};

const dnsInspectionSlice = createSlice({
  name: "dnsInspection",
  initialState,
  reducers: {
    setDnsInspectionActiveTab: (state, action: PayloadAction<DnsTabKey>) => {
      state.activeTab = action.payload;
    },

    setGeneralConfig: (
      state,
      action: PayloadAction<Partial<DnsInspectionGeneralConfig>>,
    ) => {
      state.draftConfig.general = {
        ...state.draftConfig.general,
        ...action.payload,
      };
    },

    setBlocklistConfig: (
      state,
      action: PayloadAction<Partial<DnsInspectionBlocklistConfig>>,
    ) => {
      state.draftConfig.blocklist = {
        ...state.draftConfig.blocklist,
        ...action.payload,
      };
    },

    setBlocklistDomains: (state, action: PayloadAction<string[]>) => {
      state.draftConfig.blocklist.domains = action.payload;
    },

    setDnsTunnelingConfig: (
      state,
      action: PayloadAction<Partial<DnsInspectionDnsTunnelingConfig>>,
    ) => {
      state.draftConfig.dnsTunneling = {
        ...state.draftConfig.dnsTunneling,
        ...action.payload,
      };
    },

    setDnsTunnelingIgnoreDomains: (state, action: PayloadAction<string[]>) => {
      state.draftConfig.dnsTunneling.ignoreDomains = action.payload;
    },

    setDnssecConfig: (
      state,
      action: PayloadAction<Partial<DnsInspectionDnssecConfig>>,
    ) => {
      state.draftConfig.dnssec = {
        ...state.draftConfig.dnssec,
        ...action.payload,
      };
    },

    setDnssecResolverConfig: (
      state,
      action: PayloadAction<Partial<DnsInspectionDnssecResolverConfig>>,
    ) => {
      state.draftConfig.dnssec.resolver = {
        ...state.draftConfig.dnssec.resolver,
        ...action.payload,
      };
    },

    setDnssecPrimaryResolver: (
      state,
      action: PayloadAction<Partial<DnsInspectionDnssecResolverEndpoint>>,
    ) => {
      state.draftConfig.dnssec.resolver.primary = {
        ...state.draftConfig.dnssec.resolver.primary,
        ...action.payload,
      };
    },

    setDnssecSecondaryResolver: (
      state,
      action: PayloadAction<Partial<DnsInspectionDnssecResolverEndpoint>>,
    ) => {
      state.draftConfig.dnssec.resolver.secondary = {
        ...state.draftConfig.dnssec.resolver.secondary,
        ...action.payload,
      };
    },

    setDnssecCacheConfig: (
      state,
      action: PayloadAction<Partial<DnsInspectionDnssecCacheConfig>>,
    ) => {
      state.draftConfig.dnssec.cache = {
        ...state.draftConfig.dnssec.cache,
        ...action.payload,
      };
    },

    setDnssecCacheTtlConfig: (
      state,
      action: PayloadAction<Partial<DnsInspectionDnssecCacheTtlConfig>>,
    ) => {
      state.draftConfig.dnssec.cache.ttlSeconds = {
        ...state.draftConfig.dnssec.cache.ttlSeconds,
        ...action.payload,
      };
    },

    setDnsInspectionDraftConfig: (
      state,
      action: PayloadAction<DnsInspectionConfig>,
    ) => {
      state.draftConfig = deepClone(action.payload);
    },

    applyDnsInspectionDraft: (state) => {
      state.appliedConfig = deepClone(state.draftConfig);
    },

    resetDnsInspectionAll: (state) => {
      state.draftConfig = deepClone(state.appliedConfig);
    },

    resetDnsInspectionTab: (state) => {
      if (state.activeTab === "general") {
        state.draftConfig.general = deepClone(state.appliedConfig.general);
        return;
      }

      if (state.activeTab === "blocklist") {
        state.draftConfig.blocklist = deepClone(state.appliedConfig.blocklist);
        return;
      }

      if (state.activeTab === "dnsTunneling") {
        state.draftConfig.dnsTunneling = deepClone(
          state.appliedConfig.dnsTunneling,
        );
        return;
      }

      state.draftConfig.dnssec = deepClone(state.appliedConfig.dnssec);
    },
  },
});

export const {
  setDnsInspectionActiveTab,
  setGeneralConfig,
  setBlocklistConfig,
  setBlocklistDomains,
  setDnsTunnelingConfig,
  setDnsTunnelingIgnoreDomains,
  setDnssecConfig,
  setDnssecResolverConfig,
  setDnssecPrimaryResolver,
  setDnssecSecondaryResolver,
  setDnssecCacheConfig,
  setDnssecCacheTtlConfig,
  setDnsInspectionDraftConfig,
  applyDnsInspectionDraft,
  resetDnsInspectionAll,
  resetDnsInspectionTab,
} = dnsInspectionSlice.actions;

export default dnsInspectionSlice.reducer;
