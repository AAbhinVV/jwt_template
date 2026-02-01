import bcrypt from "bcrypt";
import prisma from "../config/prisma.js";
import {redisClient} from "../config/redis.js";
import { generateTokenAndSetCookie } from "../util/generateTokenAndSetCookie.js";
import type { LoginParams, RegisterParams } from "../types/auth.types.ts";


const MAX_ATTEMPTS: number = 5;
const BLOCK_TIME_LOGIN : number  = 600; // seconds
const EXPRIRY_REGISTER : number = 60; // seconds

type LoginResult =
  | { error: "RATE_LIMIT_EXCEEDED" | "INVALID_CREDENTIALS"; message: string }
  | { userId: string };

type RegisterResult = 
  | { error: "RATE_LIMIT_EXCEEDED" | "EMAIL_ALREADY_REGISTERED"; message: string }
  | { userId: string };


export const loginUser = async ({ email, password, ip  } :LoginParams) : Promise<LoginResult> => {
  const normalizedEmail  = email.toLowerCase().trim();
  const rateLimitKey  = `login-rate-limit:${ip}:${normalizedEmail}`;

  // Rate limit check
  const attempts : string | null = await redisClient.get(rateLimitKey);
  if (attempts && parseInt(attempts) >= MAX_ATTEMPTS) {
    return {
      error: "RATE_LIMIT_EXCEEDED",
      message: "Too many login attempts. Please try again later."
    };
  }

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail }
  });

  if (!user) {
    await redisClient
      .multi()
      .incr(rateLimitKey)
      .expire(rateLimitKey, BLOCK_TIME_LOGIN)
      .exec();

    return {
      error: "INVALID_CREDENTIALS",
      message: "Invalid email or password"
    };
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    await redisClient
      .multi()
      .incr(rateLimitKey)
      .expire(rateLimitKey, BLOCK_TIME_LOGIN)
      .exec();

    return {
      error: "INVALID_CREDENTIALS",
      message: "Invalid email or password"
    };
  }

  // Clear rate limit on success
  await redisClient.del(rateLimitKey);

  return {
    userId: user.id
  };
};

export const registerUser = async ({ fullName, lastName, email, password, ip }: RegisterParams) : Promise<RegisterResult> => {
    
  const normalizedEmail = email.toLowerCase().trim();
  const rateLimitKey  = `signup-rate-limit:${ip}:${normalizedEmail}`;


  const isLimited : string| null = await redisClient.get(rateLimitKey);
    if (isLimited){
        return {
            error: "RATE_LIMIT_EXCEEDED",
            message: "Too many registration attempts. Please try again later."
            };
    } 

    await redisClient.set(rateLimitKey, 'true', { EX: EXPRIRY_REGISTER});


    const existingUser = await prisma.user.findUnique({
        where: {email: normalizedEmail}
    });

    if(existingUser) {
        return {
            error: "EMAIL_ALREADY_REGISTERED",
            message: "Email is already registered"
        };
    }

    const hashedPassword = bcrypt.hash(password, 10);
    

    const newUser = await prisma.user.create({
        data: {
            fullName,
            lastName,   
            email: normalizedEmail,
            password: hashedPassword
        }
    })

    return{ userId: newUser.id };


}