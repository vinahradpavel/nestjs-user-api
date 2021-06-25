import { ApiProperty } from '@nestjs/swagger';

export class SignInEntity {
  @ApiProperty({
    example: 'vino49@yopmal.com',
  })
  email: string;

  @ApiProperty({ example: 'passwordpassword' })
  password: string;
}

export class SignUpEntity {
  @ApiProperty({
    example: 'vino49@yopmal.com',
  })
  email: string;

  @ApiProperty({ example: 'passwordpassword' })
  password: string;
}
