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
import { natRulesApi } from "../services/natRules";
import NatRulesReducer from "../features/natRulesSlice";
import { usersApi } from "../services/users";
import ConfigReducer from "../features/configSlice";
import ConfigDiffReducer from "../features/configDiffSlice";
import UsersManagementSlice from "../features/usersManagementSlice";
import { configApi } from "../services/config";

export const store = configureStore({
  reducer: {
    usersManagement: UsersManagementSlice,
    dnsInspection: DnsInspectionReducer,
    resetPassword: ResetPasswordReducer,
    loginData: LoginDataReducer,
    ipsConfig: IpsConfigReducer,
    zonePairs: ZonePairsReducer,
    natRules: NatRulesReducer,
    config: ConfigReducer,
    configDiff: ConfigDiffReducer,
    zones: ZonesReducer,
    rules: RulesReducer,
    user: UserReducer,
    [dnsInspectionApi.reducerPath]: dnsInspectionApi.reducer,
    [ipsConfigApi.reducerPath]: ipsConfigApi.reducer,
    [zonePairsApi.reducerPath]: zonePairsApi.reducer,
    [natRulesApi.reducerPath]: natRulesApi.reducer,
    [configApi.reducerPath]: configApi.reducer,
    [usersApi.reducerPath]: usersApi.reducer,
    [rulesApi.reducerPath]: rulesApi.reducer,
    [zonesApi.reducerPath]: zonesApi.reducer,
    [authApi.reducerPath]: authApi.reducer,
  },

  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(
      dnsInspectionApi.middleware,
      zonePairsApi.middleware,
      ipsConfigApi.middleware,
      natRulesApi.middleware,
      configApi.middleware,
      usersApi.middleware,
      zonesApi.middleware,
      rulesApi.middleware,
      authApi.middleware,
    ),
});

setupListeners(store.dispatch);

export type AppDispatch = typeof store.dispatch;
export type RootState = ReturnType<typeof store.getState>;
