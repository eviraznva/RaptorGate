import {
  IsEnum,
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

export class SmtpMatchDto {
  @ApiProperty({ example: '^.*@trusted\\.com$', minLength: 1 })
  @IsString()
  @IsNotEmpty()
  @IsValidRegex()
  regex: string;

  @ApiProperty({ enum: ['allow', 'deny'], example: 'allow' })
  @IsEnum(['allow', 'deny'])
  onMatch: 'allow' | 'deny';
}

export class SmtpMatchersDto {
  @ApiProperty({ type: [SmtpMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SmtpMatchDto)
  sender: SmtpMatchDto[];

  @ApiProperty({ type: [SmtpMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SmtpMatchDto)
  recipient: SmtpMatchDto[];

  @ApiProperty({ type: [SmtpMatchDto], example: [] })
  @ValidateNested({ each: true })
  @Type(() => SmtpMatchDto)
  message: SmtpMatchDto[];
}
