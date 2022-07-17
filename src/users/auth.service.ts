import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { promisify } from 'util';
import { UsersService } from './users.service';
import { randomBytes, scrypt as _scrypt } from 'crypto';

const scrypt = promisify(_scrypt);

@Injectable()
export class AuthService {
  constructor(private usersService: UsersService) {}

  async signup(body) {
    const { email, password } = body;
    const found = await this.usersService.find(email);
    if (found.length) {
      throw new ConflictException('Email already in use.');
    }
    const salt = randomBytes(8).toString('hex');
    const hash = (await scrypt(password, salt, 32)) as Buffer;
    const hashedResult = salt + '.' + hash.toString('hex');
    const user = await this.usersService.create({
      email,
      password: hashedResult,
    });
    return user;
  }

  async signin(body) {
    const { email, password } = body;
    const [user] = await this.usersService.find(email);
    if (!user) {
      throw new NotFoundException('Email not found.');
    }

    const [salt, storedHash] = user.password.split('.');

    const hash = (await scrypt(password, salt, 32)) as Buffer;

    if (hash.toString('hex') !== storedHash) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return user;
  }
}
