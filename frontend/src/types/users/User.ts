export type UserRole = "super_admin" | "admin" | "viewer" | "operator";

export type DashboardUser = {
  id: string;
  username: string;
  createdAt: string;
  updatedAt: string;
  roles: UserRole[];
  isFirstLogin: boolean;
};
