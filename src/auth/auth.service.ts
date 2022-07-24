import {BadRequestException, ForbiddenException, Injectable} from '@nestjs/common';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { UsersService } from 'src/user/user.service';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthDto } from './dto/auth.dto';

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,
        private configService: ConfigService,
    ) {}
    async signUp(createUserDto: CreateUserDto): Promise<any> {
        // Проверка пользователя
        const userExists = await this.usersService.findByUsername(
            createUserDto.username,
        );
        if (userExists) {
            throw new BadRequestException('Пользователь уже существует');
        }

        // Hash пароля
        const hash = await this.hashPass(createUserDto.password);
        const newUser = await this.usersService.create({
            ...createUserDto,
            password: hash,
        });
        const tokens = await this.getTokens(newUser._id, newUser.username);
        await this.updateRefreshToken(newUser._id, tokens.refreshToken);
        return tokens;
    }

    async signIn(authDto: AuthDto) {
        // Check if user exists
        const user = await this.usersService.findByUsername(authDto.username);
        if (!user) throw new BadRequestException('Пользователь не существует');
        const passwordMatches = await argon2.verify(user.password, authDto.password);
        if (!passwordMatches)
            throw new BadRequestException('Неправельнйы пароль');
        const tokens = await this.getTokens(user._id, user.username);
        await this.updateRefreshToken(user._id, tokens.refreshToken);
        return tokens;
    }

    async logout(userId: string) {
        return this.usersService.update(userId, { refreshToken: null });
    }

    hashPass(pass: string) {
        return argon2.hash(pass);
    }

    async updateRefreshToken(userId: string, refreshToken: string) {
        const hashedRefreshToken = await this.hashPass(refreshToken);
        await this.usersService.update(userId, {
            refreshToken: hashedRefreshToken,
        });
    }

    async getTokens(userId: string, username: string) {
        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync(
                {
                    sub: userId,
                    username,
                },
                {
                    secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
                    expiresIn: '15s',
                },
            ),
            this.jwtService.signAsync(
                {
                    sub: userId,
                    username,
                },
                {
                    secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
                    expiresIn: '7d',
                },
            ),
        ]);

        return {
            accessToken,
            refreshToken,
        };
    }

    async refreshTokens(userId: string, refreshToken: string) {
        const user = await this.usersService.findById(userId);
        if (!user || !user.refreshToken)
            throw new ForbiddenException('Access Denied');
        const refreshTokenMatches = await argon2.verify(
            user.refreshToken,
            refreshToken,
        );
        if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');
        const tokens = await this.getTokens(user.id, user.username);
        await this.updateRefreshToken(user.id, tokens.refreshToken);
        return tokens;
    }
}