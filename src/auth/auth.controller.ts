import {
    Body,
    Controller,
    Get,
    Post,
    Req, UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import {LocalAuthGuard} from "./guard/local-auth.guard";
import {RefreshTokenGuard} from "./guard/refresh-token.guard";

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Post('signup')
    signup(@Body() createUserDto: CreateUserDto) {
        return this.authService.signUp(createUserDto);
    }

    @Post('signin')
    signin(@Body() data: AuthDto) {
        return this.authService.signIn(data);
    }

    @Get('logout')
    @UseGuards(LocalAuthGuard)
    logout(@Req() req: Request) {
        this.authService.logout(req.user['sub']);
    }

    @UseGuards(RefreshTokenGuard)
    @Get('refresh')
    refreshTokens(@Req() req: Request) {
        const userId = req.user['sub'];
        const refreshToken = req.user['refreshToken'];
        return this.authService.refreshTokens(userId, refreshToken);
    }
}