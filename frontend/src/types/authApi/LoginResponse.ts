export type LoginResponse = {
  id: string;
  username: string;
  createdAt: string;
  recoveryToken: string | null;
  isFirstLogin: boolean;
  showRecoveryToken: boolean;
  accessToken: string;
};
