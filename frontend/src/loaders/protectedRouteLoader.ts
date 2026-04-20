import { redirect } from "react-router-dom";
import { store } from "../app/store";
import type { ApiResponse } from "../types/ApiResponse";
import type { RefreshTokenResponse } from "../types/authApi/RefreshTokenResponse";

const API_URL = import.meta.env.RAPTOR_GATE_API_URL;

export const protectedRouteLoader = async function () {
  const user = store.getState().user;
  if (user.accessToken === "") return redirect("/login");

  try {
    const res = await fetch(`${API_URL}/auth/refresh`, {
      method: "POST",
      credentials: "include",
      mode: "cors",
      headers: {
        authorization: `Bearer ${user.accessToken}`,
      },
    });
    const data = (await res.json()) as ApiResponse<RefreshTokenResponse>;

    if (data.statusCode !== 201) return redirect("/login");
  } catch (err) {
    return redirect("/login");
  }
};
