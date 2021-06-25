import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  UseGuards,
  ValidationPipe,
} from '@nestjs/common';
import { ApiBody, ApiBearerAuth, ApiResponse } from '@nestjs/swagger';

import { AuthService } from './auth.service';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { AuthGuard } from '@nestjs/passport';
import { SignInEntity, SignUpEntity } from './entities/signInEntity';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @ApiBody({ type: SignUpEntity })
  @ApiResponse({ status: 201, description: 'User created' })
  @Post('/signup')
  async signUp(
    @Body(ValidationPipe) authCredentialsDto: AuthCredentialsDto,
  ): Promise<void> {
    return await this.authService.signUp(authCredentialsDto);
  }

  @ApiBody({ type: SignInEntity })
  @Post('/signin')
  async signIn(@Request() req) {
    return this.authService.signIn(req.body);
  }

  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  @Get('/me')
  async getMe(@Request() req) {
    return req.user;
  }
}
