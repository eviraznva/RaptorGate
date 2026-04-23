import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Param,
  Post,
  Put,
  Query,
  Req,
} from '@nestjs/common';
import { ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { CreateUserUseCase } from '../../application/use-cases/create-user.use-case.js';
import { DeleteUserUseCase } from '../../application/use-cases/delete-user.use-case.js';
import { EditUserUseCase } from '../../application/use-cases/edit-user.use-case.js';
import { GetAllUsersUseCase } from '../../application/use-cases/get-all-users.use-case.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { Role } from '../../domain/enums/role.enum.js';
import { RequirePermissions } from '../decorators/auth/require-permissions.decorator.js';
import { Roles } from '../decorators/auth/roles.decorator.js';
import {
  ApiCreatedEnvelope,
  ApiNoContentEnvelope,
  ApiOkEnvelope,
} from '../decorators/api-envelope-response.decorator';
import {
  ApiError400,
  ApiError401,
  ApiError403,
  ApiError404,
  ApiError409,
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator';
import { ResponseMessage } from '../decorators/response-message.decorator';
import { CreateUserDto } from '../dtos/create-user.dto';
import { CreateUserResponseDto } from '../dtos/create-user-response.dto';
import { EditUserDto } from '../dtos/edit-user.dto';
import { EditUserResponseDto } from '../dtos/edit-user-response.dto';
import { GetAllUsersResponseDto } from '../dtos/get-all-users-response.dto';
import { GetUsersQueryDto } from '../dtos/get-users-query.dto';
import { UserResponseMapper } from '../mappers/user-response.mapper';

type AuthenticatedRequest = Request & { user: { id: string } };

@ApiTags('User Management')
@Controller('user')
export class UserController {
  constructor(
    @Inject(CreateUserUseCase)
    private readonly createUserUseCase: CreateUserUseCase,
    @Inject(DeleteUserUseCase)
    private readonly deleteUserUseCase: DeleteUserUseCase,
    @Inject(EditUserUseCase) private readonly editUserUseCase: EditUserUseCase,
    @Inject(GetAllUsersUseCase)
    private readonly getAllUsersUseCase: GetAllUsersUseCase,
  ) {}

  @ApiOperation({
    summary: 'Create a new user',
    description:
      'Creates a new user with the provided username, password, and roles',
  })
  @Post()
  @Roles(Role.SuperAdmin, Role.Admin)
  @RequirePermissions(Permission.USERS_CREATE, Permission.USERS_ASSIGN_ROLE)
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: CreateUserDto })
  @ResponseMessage('User created successfully')
  @ApiCreatedEnvelope(CreateUserResponseDto)
  @ApiError400('User input validation failed')
  @ApiError401('Authorization header missing or invalid')
  @ApiError403('Insufficient permissions')
  @ApiError409('User with the same username already exists')
  @ApiError429('Too many requests')
  @ApiError500('Server error while creating user')
  async createUser(
    @Body() dto: CreateUserDto,
    @Req() request: AuthenticatedRequest,
  ): Promise<CreateUserResponseDto> {
    const result = await this.createUserUseCase.execute({ ...dto, actorUserId: request.user.id });

    const user = UserResponseMapper.toDto(result.user);

    return { user };
  }

  @ApiOperation({
    summary: 'Get all users',
    description:
      'Gets a list of all users. Requires SuperAdmin or Admin role and USERS_READ permission.',
  })
  @Get()
  @Roles(Role.SuperAdmin, Role.Admin)
  @RequirePermissions(Permission.USERS_READ)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('List of all users retrieved successfully')
  @ApiOkEnvelope(
    GetAllUsersResponseDto,
    'List of all users retrieved successfully',
  )
  @ApiError401('Authorization header missing or invalid')
  @ApiError403('Insufficient permissions to view users')
  @ApiError404('No users found')
  @ApiError429('Too many requests')
  @ApiError500('Server error while retrieving users')
  async getAllUsers(
    @Query() query: GetUsersQueryDto,
  ): Promise<GetAllUsersResponseDto> {
    const result = await this.getAllUsersUseCase.execute(query);

    const users = result.users.map((user) => UserResponseMapper.toDto(user));

    return { users };
  }

  @ApiOperation({
    summary: 'Edit an existing user',
    description:
      'Edits an existing user by their ID. Requires SuperAdmin or Admin role and USERS_EDIT permission.',
  })
  @Put(':id')
  @Roles(Role.SuperAdmin, Role.Admin)
  @RequirePermissions(Permission.USERS_UPDATE, Permission.USERS_ASSIGN_ROLE)
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: EditUserDto })
  @ResponseMessage('User updated successfully')
  @ApiOkEnvelope(EditUserResponseDto, 'User updated successfully')
  @ApiError400('User input validation failed')
  @ApiError401('Authorization header missing or invalid')
  @ApiError403('Insufficient permissions to edit user')
  @ApiError404('User not found')
  @ApiError409('Conflict occurred while editing user')
  @ApiError429('Too many requests')
  @ApiError500('Server error while editing user')
  async editUser(
    @Body() dto: EditUserDto,
    @Param('id') id: string,
    @Req() request: AuthenticatedRequest,
  ): Promise<EditUserResponseDto> {
    const result = await this.editUserUseCase.execute({ ...dto, id, actorUserId: request.user.id });

    const editedUser = UserResponseMapper.toDto(result.user);

    return { user: editedUser };
  }

  @ApiOperation({
    summary: 'Delete a user',
    description:
      'Deletes a user by their ID. Requires SuperAdmin or Admin role and USERS_DELETE permission.',
  })
  @Delete(':id')
  @Roles(Role.SuperAdmin, Role.Admin)
  @RequirePermissions(Permission.USERS_DELETE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiNoContentEnvelope()
  @ApiError401('Authorization header missing or invalid')
  @ApiError403('Insufficient permissions to delete user')
  @ApiError404('User not found')
  @ApiError409('Conflict occurred while deleting user')
  @ApiError429('Too many requests')
  @ApiError500('Server error while deleting user')
  async deleteUser(
    @Param('id') id: string,
    @Req() request: AuthenticatedRequest,
  ): Promise<void> {
    await this.deleteUserUseCase.execute({ userId: id, actorUserId: request.user.id });
  }
}
