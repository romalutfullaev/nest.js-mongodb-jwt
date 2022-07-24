import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import {JwtConstants} from "../constants";

type JwtPayload = {
    sub: string;
    username: string;
};

@Injectable()
export class AccessStrategy extends PassportStrategy(Strategy, 'local') {
    constructor() {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: JwtConstants.secretKey,
        });
    }

    validate(payload: JwtPayload) {
        return payload;
    }
}