import {
  BadGatewayException,
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';

import { Repository } from 'typeorm';

import * as bcrypt from 'bcrypt';

import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { CreateUserDto, LoginUserDto } from './dto';
import { JwtPayload } from './interfaces/jwt-payload.interfaces';
import { JwtService, TokenExpiredError } from '@nestjs/jwt';
import { UpdatePasswordDto } from './dto/update-password.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,

    private readonly jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto) {
    try {
      const { password, ...userData } = createUserDto;

      const user = this.userRepository.create({
        ...userData,
        password: bcrypt.hashSync(password, 10),
      });

      await this.userRepository.save(user);
      delete user.password;

      return {
        ...user,
        token: this.getJwtToken({ id: user.id }),
      };
    } catch (error) {
      this.handleDBErrors(error);
    }
  }

  async updatePassword(userId: string, updatePasswordDto: UpdatePasswordDto) {
    const { email, newPassword } = updatePasswordDto;

    // Encuentra el usuario por su ID
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['id', 'password', 'email'],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verifica si el email proporcionado coincide con el email del usuario
    if (user.email !== email) {
      throw new UnauthorizedException('Email does not match');
    }

    // Encripta la nueva contraseña y guarda el usuario actualizado
    user.password = bcrypt.hashSync(newPassword, 10);
    await this.userRepository.save(user);

    return { message: 'Password updated successfully' };
  }

  async login(loginUserDto: LoginUserDto) {
    const { password, email } = loginUserDto;

    const user = await this.userRepository.findOne({
      where: { email },
      select: { email: true, password: true, id: true },
    });

    if (!user)
      throw new UnauthorizedException('Credentials are not valid (email) ');

    if (!bcrypt.compareSync(password, user.password))
      throw new UnauthorizedException('Credentiasl are not valid (password)');

    return {
      ...user,
      token: this.getJwtToken({ id: user.id }),
    };
  }

  async checkAuthStatus(user: User) {
    return {
      ...user,
      token: this.getJwtToken({ id: user.id }),
    };
  }

  private getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }

  private handleDBErrors(error: any): never {
    if (error.code === '23505') throw new BadRequestException(error.detail);

    console.log(error);

    throw new InternalServerErrorException('Please check server logs');
  }
}
