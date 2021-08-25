import { getCustomRepository } from "typeorm"
import { compare } from "bcryptjs"
import { sign } from "jsonwebtoken"
import { UsersRepositories } from "../repositories/UsersRepositories"


interface IAuthenticateRequest {
  email: string;
  password: string;
}

class AuthenticateUserService {

  async execute ({email, password}: IAuthenticateRequest) {
    const usersRepositories = getCustomRepository(UsersRepositories)

    // Verificar se o email existe
    const user = await usersRepositories.findOne({
      email
    });

    if(!user){
      throw new Error("Email ou senha incorreta")
    }

    // Verificar se senha está correta
    const passwordMatch = await compare(password, user.password);

    if(!passwordMatch){
      throw new Error("Email ou senha incorreta")
    }

    //Gerar Token
    const token = sign({
      email: user.email
    }, "100da48a8e2442de89f3b5310fa5d65a",{ //md5 generator
      subject: user.id,
      expiresIn: "1d"
    } );

    return token;
  }
}

export {AuthenticateUserService}