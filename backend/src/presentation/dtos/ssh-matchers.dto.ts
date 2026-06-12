import {
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsString,
  ValidateNested,
} from 'class-validator';
import {
  registerDecorator,
  ValidationOptions,
  ValidationArguments,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

function IsValidRegex(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'isValidRegex',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: string): boolean {
          if (typeof value !== 'string' || value.length === 0) return false;
          try {
            new RegExp(value);
            return true;
          } catch {
            return false;
          }
        },
        defaultMessage(args: ValidationArguments) {
          return `${args.property} has invalid regular expression syntax`;
        },
      },
    });
  };
}

export class SshMatchDto {
  @ApiProperty({ example: '^OpenSSH_.*$', minLength: 1 })
  @IsString()
  @IsNotEmpty()
  @IsValidRegex()
  regex: string;

  @ApiProperty({ enum: ['allow', 'deny'], example: 'allow' })
  @IsEnum(['allow', 'deny'])
  onMatch: 'allow' | 'deny';
}

export class SshReasonMatchDto {
  @ApiProperty({ type: [Number], example: [2, 14] })
  @IsInt({ each: true })
  codes: number[];

  @ApiProperty({ enum: ['allow', 'deny'], example: 'deny' })
  @IsEnum(['allow', 'deny'])
  onMatch: 'allow' | 'deny';
}

export class SshMatchersDto {
  @ApiProperty({ type: [SshMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SshMatchDto)
  clientSoftware: SshMatchDto[];

  @ApiProperty({ type: [SshMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SshMatchDto)
  serverSoftware: SshMatchDto[];

  @ApiProperty({ type: [SshMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SshMatchDto)
  clientProtoVersion: SshMatchDto[];

  @ApiProperty({ type: [SshMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SshMatchDto)
  serverProtoVersion: SshMatchDto[];

  @ApiProperty({ type: [SshMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SshMatchDto)
  kex: SshMatchDto[];

  @ApiProperty({ type: [SshMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SshMatchDto)
  hostKeyAlg: SshMatchDto[];

  @ApiProperty({ type: [SshMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SshMatchDto)
  cipher: SshMatchDto[];

  @ApiProperty({ type: [SshMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SshMatchDto)
  mac: SshMatchDto[];

  @ApiProperty({ type: [SshMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SshMatchDto)
  compression: SshMatchDto[];

  @ApiProperty({ type: [SshMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SshMatchDto)
  hostKeyType: SshMatchDto[];

  @ApiProperty({ type: [SshReasonMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SshReasonMatchDto)
  disconnectReason: SshReasonMatchDto[];
}
