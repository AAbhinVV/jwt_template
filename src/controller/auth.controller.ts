import { registerSchema, loginSchema } from "../config/zod.js";
import bcrypt from "bcrypt";
import prisma from "../config/prisma.js";
import {generateTokenAndSetCookie, verifyRefreshToken } from "../util/generateTokenAndSetCookie.js";
import { redisClient } from "../config/redis.js";
import { loginUser, registerUser } from "../service/auth.service.js";
import { register } from "node:module";
import type { Request, Response } from "express";

type ValidationErrors = 
    { field: string; message: string; code: string };

const login = async (req : Request, res : Response) : Promise<void>  => {
  try {
    const validation = loginSchema.safeParse(req.body);

    if(!validation.success) {
        const zodErrors = validation.error.errors;

        let firstErrorMessage = "Validation error";
        let allErrors: ValidationErrors[] = [];
        

        if(Array.isArray(zodErrors)) {
            allErrors = zodErrors.map((issue) => ({
                field: issue.path ? issue.path.join('.') : 'unknown',
                message: issue.message || "validation error",
                code: issue.code
            }))
        
            firstErrorMessage = allErrors[0]?.message ?? "validation Error";
        }
        res.status(422).json({success: false, message: firstErrorMessage})
        return;
    }

    const {email, password} = validation.data;

    if(!email || !password) {
        res.status(400).json({success: false, message: "All field are required"});
        return;
    }

    const result = await loginUser({email, password, ip: req.ip});

    if("error" in result){
        if(result.error === "RATE_LIMIT_EXCEEDED"){
        res.status(429).json({success: false, message: result.message})
        return;

        }

        if(result.error === "INVALID_CREDENTIALS"){
            res.status(401).json({success:false, message: result.message})
            return;
        }
    }

    const {accessToken, refreshToken} = generateTokenAndSetCookie(res, result.userId);

    if(!accessToken || !refreshToken) {
        res.status(500).json({success: false, message: "Token generation failed"});
        return;
    }

    res.status(200).json({
        success: true,
        refresh_token: refreshToken,
        message: "Login successful"
    });


  } catch (error: unknown) {
    if(error instanceof Error){
        console.error(error.message);
    }
    res.sendStatus(503);
  }
}

const signUp = async (req: Request, res: Response) : Promise<void> => {
    try {
        const validation : ReturnType<typeof registerSchema.safeParse> = registerSchema.safeParse(req.body)

        if(!validation.success){
            const zodErrors = validation.error;
            let firstErrorMessage = "Validation error";
            let allErrors = [];

            if(zodErrors?.errors && Array.isArray(zodErrors.errors)){
                allErrors = zodErrors.errors.map((issue) => ({
                    field: issue.path ? issue.path.join('.') : 'unknown',
                    message: issue.message || "validation error",
                    code: issue.code,
                }))

                firstErrorMessage = allErrors[0].message || "validation error";
            }

            res.status(422).json({success: false, message: firstErrorMessage});
            return;
        }

        const { fullName, lastName, email, password} = validation.data;


        if(!fullName || !lastName || !email || !password) {
            res.status(400).json({success: false, message: 'All fields are required'});
            return;
        }

        
        const result = registerUser({fullName, lastName, email, password, ip: req.ip});

        if(result.error === "RATE_LIMIT_EXCEEDED"){
            res.status(429).json({success: false, message: result.message});
            return;
        }

        if(result.error === "EMAIL_ALREADY_REGISTERED"){
            res.status(409).json({success: false, message: result.message});
            return;
        }

        const {accessToken, refreshToken} = generateTokenAndSetCookie(res, result.userId);

        if(!accessToken || !refreshToken) {
            res.status(500).json({success: false, message: "Token generation failed"});
            return;
        }

        res.status(200).json({
        success: true,
        refresh_token: refreshToken,
        message: "Registration successful"
    });

    } catch (error) {
        console.error(error.message);
        res.status(503)
    }
}

const logout = (req, res) => {
  const cookies = req.signedCookies;
  if(!cookies?.refreshToken) res.status(204);

  res.clearCookie("refreshToken", {
    signed: true,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: parseExpiryToMillis(REFRESH_TOKEN_EXPIRY)
  })

  res.clearCookie("accessToken")

  res.status(200).json({success: true, message: "Logged out successfully"});
}

const refreshToken = (req, res) => {
  const refreshTokne = req.signedCookies?.refreshToken || req.signedCookies?.refreshToken;

  if(!refreshToken){
    res.status(401).json({success: false, message: "No refresh token provided"});
    return;
  }

  const decoded = verifyRefreshToken(refreshToken);

  if(!decoded){
    res.status(403).json({success: false, message: "Forbidden: Invalid refresh token"});
    return;
  }

  generateAccessToken(decoded.user.id);

  jwt.verify(refreshToken, JWT_REFRESH_SECRET, 
    async (err, user) => {
        if(err) {
            res.status(403).json({success: false, message: "Forbidden: Invalid refresh token"});
            return;
        }

        const founduser = await prisma.user.findUnique({
            where: {id: user.userId}
        })

        if(!founduser){
            res.status(403).json({success: false, message: "Forbidden: User not found"});
            return;
        }

        const accessToken = jwt.sign({userId: founduser.id}, JWT_ACCESS_SECRET, {expiresIn: ACCESS_TOKEN_EXPIRY});

        res.json({accessToken});

        res.status(200).json({
            success: true,
            access_token: accessToken,
            message: "Access token refreshed successfully"
        });
})
}

export default {
    login,
    signUp,
    logout,
    refreshToken
};