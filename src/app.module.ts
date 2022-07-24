import {MiddlewareConsumer, Module, NestModule} from '@nestjs/common';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import {GlobalMiddleware} from "./global.middleware";



@Module({
  imports: [UserModule, AuthModule, ]
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
        .apply(GlobalMiddleware)
        .forRoutes('*');
  }
}
