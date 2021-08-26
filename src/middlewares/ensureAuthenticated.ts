import { Request, Response, NextFunction } from "express";
import { verify } from "jsonwebtoken";

interface IPayload {
  sub: string;
}

export function ensureAuthenticated(
  request: Request,
  response: Response,
  next: NextFunction
) {
  // Receber o token
  const authToken = request.headers.authorization;

  // Validar se token está preenchido
  if (!authToken) {
    return response.status(401).end();
  }

  const [, token] = authToken.split(" ");

  try {
    // Validar se token é válido
    const { sub } = verify(
      token,
      "100da48a8e2442de89f3b5310fa5d65a"
    ) as IPayload;

    // Recuperar informações do usuário
    request.user_id = sub;

    return next();
  } catch (err) {
    return response.status(401).end();
  }
}