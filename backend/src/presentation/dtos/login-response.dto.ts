import { ApiProperty } from "@nestjs/swagger";

export class LoginResponseDto {
  @ApiProperty({
    description: "Unique user identifier",
    example: "123e4567-e89b-12d3-a456-426614174000",
  })
  id: string;

  @ApiProperty({
    description: "Username",
    example: "jankowal",
  })
  username: string;

  @ApiProperty({
    description: "Account creation timestamp",
    example: "2024-03-14T10:30:00Z",
  })
  createdAt: Date;

  @ApiProperty({
    description: "JWT access token for authentication",
    example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  })
  accessToken: string;

  @ApiProperty({
    description: "Token used for password recovery, showed only on first login",
    example: "yz9a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p3q2r1s0t...",
  })
  recoveryToken: string | null;

  @ApiProperty({
    description: "Indicates if this is the user's first login",
    example: true,
  })
  isFirstLogin: boolean;

  @ApiProperty({
    description: "Indicates if the recovery token should be shown to the user",
    example: true,
  })
  showRecoveryToken: boolean;
}
