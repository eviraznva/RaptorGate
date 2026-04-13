import { configureStore } from "@reduxjs/toolkit";
import UserReducer from "../features/userSlice";
import LoginDataReducer from "../features/loginDataSlice";
import DnsInspectionReducer from "../features/dnsInspectionSlice";
import IpsConfigReducer from "../features/ipsConfigSlice";
import ResetPasswordReducer from "../features/resetPasswordSlice";
import { authApi } from "../services/auth";
import { dnsInspectionApi } from "../services/dnsInspection";
import { setupListeners } from "@reduxjs/toolkit/query";

export const store = configureStore({
  reducer: {
    user: UserReducer,
    loginData: LoginDataReducer,
    dnsInspection: DnsInspectionReducer,
    ipsConfig: IpsConfigReducer,
    resetPassword: ResetPasswordReducer,
    [authApi.reducerPath]: authApi.reducer,
    [dnsInspectionApi.reducerPath]: dnsInspectionApi.reducer,
  },

  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(
      authApi.middleware,
      dnsInspectionApi.middleware,
    ),
});

setupListeners(store.dispatch);

export type AppDispatch = typeof store.dispatch;
export type RootState = ReturnType<typeof store.getState>;
