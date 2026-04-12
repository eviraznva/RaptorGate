import { fetchBaseQuery, type BaseQueryFn } from "@reduxjs/toolkit/query";
import { Mutex } from "async-mutex";
import { clearUser, updateAccessToken } from "../features/userSlice";
import type { ApiFailure, ApiSuccess } from "../types/ApiResponse";
import type { RefreshTokenResponse } from "../types/authApi/RefreshTokenResponse";

export const baseQuery = fetchBaseQuery({
  baseUrl: `${import.meta.env.RAPTOR_GATE_API_URL}`,
  credentials: "include",
  mode: "cors",
});

const mutex = new Mutex();

export const baseQueryWithReauth: BaseQueryFn = async (
  args,
  api,
  extraOptions,
) => {
  await mutex.waitForUnlock();

  let result = await baseQuery(args, api, extraOptions);

  if (result.error?.status === 401) {
    if (!mutex.isLocked()) {
      const release = await mutex.acquire();

      try {
        const refreshResult = await baseQuery(
          { url: "/auth/refresh", method: "POST", credentials: "include" },
          api,
          extraOptions,
        );

        if (refreshResult.data) {
          const token = refreshResult as ApiSuccess<RefreshTokenResponse>;

          api.dispatch(updateAccessToken(token.data.accessToken));

          result = await baseQuery(args, api, extraOptions); // retry
        } else {
          api.dispatch(clearUser());
        }
      } finally {
        release();
      }
    } else {
      await mutex.waitForUnlock();

      result = await baseQuery(args, api, extraOptions);
    }
  }

  if (result.error) return { error: result.error.data as ApiFailure };

  return result;
};
