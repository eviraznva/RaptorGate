// Application layer DTO - clean, without framework decorators
export class LoginResponseDto {
  id: string;
  username: string;
  createdAt: Date;
  accessToken: string;
}
