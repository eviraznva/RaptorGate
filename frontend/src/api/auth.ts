import api from "./axios";
import type { AuthResponse } from "../types";

// 🔐 LOGIN
export const loginRequest = async (
  username: string,
  password: string
): Promise<AuthResponse> => {
  const res = await api.post<AuthResponse>("/auth/login", {
    username,
    password,
  });

  return res.data;
};