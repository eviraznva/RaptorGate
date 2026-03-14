import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  UseFilters,
} from '@nestjs/common';
import {
  ErrorResponseDto,
  ValidationErrorResponseDto,
} from '../dtos/error-response.dto';
import { LoginUserUseCase } from 'src/application/use-cases/login-user.use-case';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { DomainExceptionFilter } from '../filters/domain-exception.filter';
import { IsPublic } from 'src/infrastructure/decorators/public.decorator';
import { LoginResponseDto } from '../dtos/login-response.dto';
import { LoginDto } from '../dtos/login.dto';

@UseFilters(DomainExceptionFilter)
@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(@Inject() private readonly loginUserUseCase: LoginUserUseCase) {}

  @IsPublic()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'User login',
    description:
      'Authenticates user with username and password, returns JWT access token',
  })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    type: LoginResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Validation error - invalid request body',
    type: ValidationErrorResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid credentials',
    type: ErrorResponseDto,
  })
  async login(@Body() loginDto: LoginDto): Promise<LoginResponseDto> {
    const applicationDto = {
      username: loginDto.username,
      password: loginDto.password,
    };

    const result = await this.loginUserUseCase.execute(applicationDto);

    return result;
  }
}
