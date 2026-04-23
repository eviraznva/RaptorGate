export class EditUserDto {
  id: string;
  actorUserId: string;
  username?: string;
  password?: string;
  roles?: string[];
}
