import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import {UserModule} from "../user/user.module";
import {PassportModule} from "@nestjs/passport";
import {AccessStrategy} from "./strategy/access.strategy";
import {JwtStrategy} from "./strategy/jwt.strategy";
import {JwtModule} from "@nestjs/jwt";
import {JwtConstants} from "./constants";
import {RefreshTokenStrategy} from "./strategy/refresh-strategy";
import {ConfigService} from "@nestjs/config";

@Module({
  imports: [
      UserModule,
      JwtModule.register({
      secret: JwtConstants.secretKey,
      signOptions: {expiresIn: '15s'}
      }),
      PassportModule
  ],
  providers: [AuthService, AccessStrategy, JwtStrategy, RefreshTokenStrategy, ConfigService],
  controllers: [AuthController]
})
export class AuthModule {}
