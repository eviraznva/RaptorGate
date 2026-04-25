// Wewnetrzny DTO use-case'a. sourceIp pochodzi z requestu/connection,
// nigdy z body — kontroler wstrzykuje go z req.ip (Issue 3 wymaganie).
export class AuthenticateIdentityDto {
  username: string;
  password: string;
  sourceIp: string;
}
