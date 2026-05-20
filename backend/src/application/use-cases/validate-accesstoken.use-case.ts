import { Inject, Injectable } from "@nestjs/common";
import { AccessTokenIsInvalidException } from "src/domain/exceptions/acces-token-is-invalid.exception";
import {
  type ITokenService,
  TOKEN_SERVICE_TOKEN,
} from "../ports/token-service.interface";

@Injectable()
export class ValidateAccessTokenUseCase {
  constructor(
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
  ) {}

  async execute(accessToken: string): Promise<boolean> {
    const isValid = await this.tokenService.verifyAccessToken(accessToken);

    if (!isValid) throw new AccessTokenIsInvalidException();

    if (isValid) return true;

    return false;
  }
}
