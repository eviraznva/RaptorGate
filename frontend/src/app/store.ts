import { configureStore } from "@reduxjs/toolkit";
import UserReducer from "../features/userSlice";
import LoginDataReducer from "../features/loginDataSlice";
import DnsInspectionReducer from "../features/dnsInspectionSlice";
import IpsConfigReducer from "../features/ipsConfigSlice";
import ResetPasswordReducer from "../features/resetPasswordSlice";
import { authApi } from "../services/auth";
import { dnsInspectionApi } from "../services/dnsInspection";
import { setupListeners } from "@reduxjs/toolkit/query";
import { ipsConfigApi } from "../services/ipsConfig";
import { rulesApi } from "../services/rules";
import RulesReducer from "../features/rulesSlice";
import { zonesApi } from "../services/zones";
import ZonesReducer from "../features/zonesSlice";
import { zonePairsApi } from "../services/zonePairs";
import ZonePairsReducer from "../features/zonePairsSlice";
import { zoneInterfacesApi } from "../services/zoneInterfaces";
import ZoneInterfacesReducer from "../features/zoneInterfacesSlice";
import { natRulesApi } from "../services/natRules";
import NatRulesReducer from "../features/natRulesSlice";
import { usersApi } from "../services/users";
import ConfigReducer from "../features/configSlice";
import ConfigDiffReducer from "../features/configDiffSlice";
import UsersManagementSlice from "../features/usersManagementSlice";
import { configApi } from "../services/config";
import SessionsReducer from "../features/sessionsSlice";
import { identityConfigApi } from "../services/identityConfig";
import { identitySessionsApi } from "../services/identitySessions";
import { secretsApi } from "../services/secrets";
import { decryptionExclusionsApi } from "../services/decryptionExclusions";
import { decryptionFailurePolicyApi } from "../services/decryptionFailurePolicy";
import { decryptionMirrorApi } from "../services/decryptionMirror";
import { sslBypassApi } from "../services/sslBypass";

export const store = configureStore({
  reducer: {
    usersManagement: UsersManagementSlice,
    dnsInspection: DnsInspectionReducer,
    resetPassword: ResetPasswordReducer,
    loginData: LoginDataReducer,
    ipsConfig: IpsConfigReducer,
    zonePairs: ZonePairsReducer,
    zoneInterfaces: ZoneInterfacesReducer,
    natRules: NatRulesReducer,
    config: ConfigReducer,
    configDiff: ConfigDiffReducer,
    sessions: SessionsReducer,
    zones: ZonesReducer,
    rules: RulesReducer,
    user: UserReducer,
    [dnsInspectionApi.reducerPath]: dnsInspectionApi.reducer,
    [ipsConfigApi.reducerPath]: ipsConfigApi.reducer,
    [zonePairsApi.reducerPath]: zonePairsApi.reducer,
    [zoneInterfacesApi.reducerPath]: zoneInterfacesApi.reducer,
    [natRulesApi.reducerPath]: natRulesApi.reducer,
    [configApi.reducerPath]: configApi.reducer,
    [usersApi.reducerPath]: usersApi.reducer,
    [identityConfigApi.reducerPath]: identityConfigApi.reducer,
    [identitySessionsApi.reducerPath]: identitySessionsApi.reducer,
    [secretsApi.reducerPath]: secretsApi.reducer,
    [decryptionExclusionsApi.reducerPath]: decryptionExclusionsApi.reducer,
    [decryptionFailurePolicyApi.reducerPath]: decryptionFailurePolicyApi.reducer,
    [decryptionMirrorApi.reducerPath]: decryptionMirrorApi.reducer,
    [sslBypassApi.reducerPath]: sslBypassApi.reducer,
    [rulesApi.reducerPath]: rulesApi.reducer,
    [zonesApi.reducerPath]: zonesApi.reducer,
    [authApi.reducerPath]: authApi.reducer,
  },

  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(
      dnsInspectionApi.middleware,
      zonePairsApi.middleware,
      zoneInterfacesApi.middleware,
      ipsConfigApi.middleware,
      natRulesApi.middleware,
      configApi.middleware,
      usersApi.middleware,
      identityConfigApi.middleware,
      identitySessionsApi.middleware,
      secretsApi.middleware,
      decryptionExclusionsApi.middleware,
      decryptionFailurePolicyApi.middleware,
      decryptionMirrorApi.middleware,
      sslBypassApi.middleware,
      zonesApi.middleware,
      rulesApi.middleware,
      authApi.middleware,
    ),
});

setupListeners(store.dispatch);

export type AppDispatch = typeof store.dispatch;
export type RootState = ReturnType<typeof store.getState>;
