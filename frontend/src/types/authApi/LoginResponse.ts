export type LoginResponse = {
  id: string;
  username: string;
  createdAt: string;
  recoveryToken: string | null;
  isFirstLogin: boolean;
  showRecoveryToken: boolean;
  accessToken: string;
  roles?: string[];
  authProvider?: string;
  authProfileId?: string | null;
};
