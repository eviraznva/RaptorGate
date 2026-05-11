import axios from "axios";
import type { InternalAxiosRequestConfig, AxiosError } from "axios";

const api = axios.create({
  baseURL: "https://localhost:3000",
  withCredentials: true, // 🔥 KLUCZOWE (cookie!)
});

// 🔐 REQUEST INTERCEPTOR
api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = localStorage.getItem("access_token");

  if (token) {
    config.headers.set("Authorization", `Bearer ${token}`);
  }

  return config;
});

// 🔁 RESPONSE INTERCEPTOR (COOKIE REFRESH)
api.interceptors.response.use(
  (res) => res,
  async (error: AxiosError) => {
    if (!error.config) return Promise.reject(error);

    const originalRequest = error.config as InternalAxiosRequestConfig & {
      _retry?: boolean;
    };

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // 🔥 NIE wysyłamy refresh_token — cookie robi to za nas
        const res = await axios.post(
          "https://localhost:3000/auth/refresh",
          {},
          { withCredentials: true }
        );

        const newAccessToken = (res.data as any).accessToken;

        localStorage.setItem("access_token", newAccessToken);

        originalRequest.headers.set(
          "Authorization",
          `Bearer ${newAccessToken}`
        );

        return api(originalRequest);
      } catch (err) {
        localStorage.clear();
        window.location.href = "/login";
        return Promise.reject(err);
      }
    }

    return Promise.reject(error);
  }
);

export default api;