import { ApiProperty } from '@nestjs/swagger';

export class SuccessEnvelopeDto<T = unknown> {
  @ApiProperty({ example: 201 })
  statusCode: number;

  @ApiProperty({ example: 'User created...' })
  message: string;

  @ApiProperty({ nullable: false })
  data: T;
}

export class ErrorEnvelopeDto {
  @ApiProperty({ example: 400 })
  statusCode: number;

  @ApiProperty({ example: 'Username must be at least 3 characters' })
  message: string;

  @ApiProperty({ example: 'Bad Request' })
  error: string;
}
