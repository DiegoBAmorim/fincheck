import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SigninDto } from './dto/signin.dto';
import { SignUpDto } from './dto/signup.dto';
import { IsPublic } from 'src/shared/decorators/isPublic';

@IsPublic()
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signin')
  signin(@Body() singinDto: SigninDto) {
    return this.authService.signin(singinDto);
  }

  @Post('signUp')
  create(@Body() signupDto: SignUpDto) {
    return this.authService.signup(signupDto);
  }
}
