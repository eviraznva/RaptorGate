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

export const store = configureStore({
  reducer: {
    dnsInspection: DnsInspectionReducer,
    resetPassword: ResetPasswordReducer,
    loginData: LoginDataReducer,
    ipsConfig: IpsConfigReducer,
    zones: ZonesReducer,
    zonePairs: ZonePairsReducer,
    natRules: NatRulesReducer,
    rules: RulesReducer,
    user: UserReducer,
    [dnsInspectionApi.reducerPath]: dnsInspectionApi.reducer,
    [ipsConfigApi.reducerPath]: ipsConfigApi.reducer,
    [rulesApi.reducerPath]: rulesApi.reducer,
    [zonesApi.reducerPath]: zonesApi.reducer,
    [zonePairsApi.reducerPath]: zonePairsApi.reducer,
    [natRulesApi.reducerPath]: natRulesApi.reducer,
    [authApi.reducerPath]: authApi.reducer,
  },

  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(
      dnsInspectionApi.middleware,
      ipsConfigApi.middleware,
      rulesApi.middleware,
      zonesApi.middleware,
      zonePairsApi.middleware,
      natRulesApi.middleware,
      authApi.middleware,
    ),
});

setupListeners(store.dispatch);

export type AppDispatch = typeof store.dispatch;
export type RootState = ReturnType<typeof store.getState>;
