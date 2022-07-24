import { Module } from '@nestjs/common';
import { UsersService } from './user.service';
import { UsersController } from './user.controller';
import { DatabaseModule } from "../database/database.module";
import { userProviders } from "./user.providers";

@Module({
  imports: [
      DatabaseModule,
  ],
  controllers: [UsersController],
  providers: [
      UsersService,
      ...userProviders
  ],
  exports: [UsersService]
})
export class UserModule {}
