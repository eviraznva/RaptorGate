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
} from '@nestjs/common';
import {
  ApiError400,
  ApiError401,
  ApiError403,
  ApiError404,
  ApiError409,
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator';
import {
  ApiCreatedEnvelope,
  ApiNoContentEnvelope,
  ApiOkEnvelope,
} from '../decorators/api-envelope-response.decorator';
import { RequirePermissions } from 'src/infrastructure/decorators/require-permissions.decorator';
import { GetAllUsersUseCase } from 'src/application/use-cases/get-all-users.use-case';
import { DeleteUserUseCase } from 'src/application/use-cases/delete-user.use-case';
import { CreateUserUseCase } from 'src/application/use-cases/create-user.use-case';
import { EditUserUseCase } from 'src/application/use-cases/edit-user.use-case';
import { GetAllUsersResponseDto } from '../dtos/get-all-users-response.dto';
import { ResponseMessage } from '../decorators/response-message.decorator';
import { CreateUserResponseDto } from '../dtos/create-user-response.dto';
import { Roles } from 'src/infrastructure/decorators/roles.decorator';
import { EditUserResponseDto } from '../dtos/edit-user-response.dto';
import { ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Permission } from 'src/domain/enums/permissions.enum';
import { CreateUserDto } from '../dtos/create-user.dto';
import { EditUserDto } from '../dtos/edit-user.dto';
import { Role } from 'src/domain/enums/role.enum';

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
  async createUser(@Body() dto: CreateUserDto): Promise<CreateUserResponseDto> {
    const user = await this.createUserUseCase.execute(dto);
    return user;
  }

  @ApiOperation({
    summary: 'Get all users',
    description:
      'Gets a list of all users. Requires SuperAdmin or Admin role and USERS_READ permission.',
  })
  @Get()
  @Roles(Role.Viewer)
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
  async getAllUsers(): Promise<GetAllUsersResponseDto> {
    return await this.getAllUsersUseCase.execute();
  }

  @ApiOperation({
    summary: 'Edit an existing user',
    description:
      'Edits an existing user by their ID. Requires SuperAdmin or Admin role and USERS_EDIT permission.',
  })
  @Put(':id')
  @Roles(Role.Admin)
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
  ): Promise<EditUserResponseDto> {
    const editedUser = await this.editUserUseCase.execute({ ...dto, id });
    return editedUser;
  }

  @ApiOperation({
    summary: 'Delete a user',
    description:
      'Deletes a user by their ID. Requires SuperAdmin or Admin role and USERS_DELETE permission.',
  })
  @Delete(':id')
  @Roles(Role.Operator)
  @RequirePermissions(Permission.USERS_DELETE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiNoContentEnvelope()
  @ApiError401('Authorization header missing or invalid')
  @ApiError403('Insufficient permissions to delete user')
  @ApiError404('User not found')
  @ApiError409('Conflict occurred while deleting user')
  @ApiError429('Too many requests')
  @ApiError500('Server error while deleting user')
  async deleteUser(@Param('id') id: string): Promise<void> {
    await this.deleteUserUseCase.execute({ userId: id });
  }
}
