import type { UserRole } from "../../types/users/User";

type UserRoleOption = {
  role: UserRole;
  description: string;
};

export const USER_ROLE_OPTIONS: UserRoleOption[] = [
  { role: "super_admin", description: "Full administrative scope" },
  { role: "admin", description: "Operational dashboard management" },
  { role: "viewer", description: "Read-only access" },
  { role: "operator", description: "Traceability and review" },
];
