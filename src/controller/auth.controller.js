import { registerSchema, loginSchema } from "../config/zod";
import bcrypt from "bcrypt";
import prisma from "../config/prisma";
import generateTokenAndSetCookie, { verifyRefreshToken } from "../util/generateTokenAndSetCookie.js";
import { redisClient } from "../config/redis.js";
import { loginUser, registerUser } from "../service/auth.service.js";
import { register } from "node:module";

const login = async (req, res) => {
  try {
    const validation = loginSchema.parse(req.body);

    if(!validation.success) {
        const zodErrors = validation.error;

        let firstErrorMessage = "Validation error";
        let allErrors = [];

        if(zodErrors?.errors && Array.isArray(zodErrors.errors)) {
            allErrors = zodErrors.errors.map((issue) => ({
                field: issue.path ? issue.path.join('.') : 'unknown',
                message: issue.message || "validation error",
                code: issue.code
            }))
        
            firstErrorMessage = allErrors[0].message || "validation Error";
        }
        return res.status(422).json({success: false, message: firstErrorMessage})
    }

    const {email, password} = validation.data;

    if(!email || !password) {
        return res.status(400).json({success: false, message: "All field are required"});
    }

    const result = loginUser({email, password, ip: req.ip});

    if(result.error === "RATE_LIMIT_EXCEEDED"){
        return res.status(429).json({success: false, message: result.message})

    }

    if(result.error === "INVALID_CREDENTIALS"){
        return res.status(401).json({success:false, message: result.message})
    }

    const {accessToken, refreshToken} = generateTokenAndSetCookie(res, user.id);

    if(!accessToken || !refreshToken) {
        return res.status(500).json({success: false, message: "Token generation failed"});
    }

    res.status(200).json({
        success: true,
        refresh_token: refreshToken,
        message: "Login successful"
    });


  } catch (error) {
    console.log(error.message);
    res.sendStatus(503);
  }
}

const signUp = async (req, res) => {
    try {
        const validation = registerSchema.safeParse(req.body)

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

            return res.status(422).json({success: false, message: firstErrorMessage});
        }

        const { fullName, lastName, email, password} = validation.data;


        if(!fullName || !lastName || !email || !password) {
            return res.status(400).json({success: false, message: 'All fields are required'});
        }

        
        const result = registerUser({fullName, lastName, email, password, ip: req.ip});

        if(result.error === "RATE_LIMIT_EXCEEDED"){
            return res.status(429).json({success: false, message: result.message});
        }

        if(result.error === "EMAIL_ALREADY_REGISTERED"){
            return res.status(409).json({success: false, message: result.message});
        }

        const {accessToken, refreshToken} = generateTokenAndSetCookie(res, result.userId);

        if(!accessToken || !refreshToken) {
            return res.status(500).json({success: false, message: "Token generation failed"});
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
    return res.status(401).json({success: false, message: "No refresh token provided"});
  }

  const decoded = verifyRefreshToken(refreshToken);

  if(!decoded){
    return res.status(403).json({success: false, message: "Forbidden: Invalid refresh token"});
  }

  generateAccessToken(decoded.user.id);

  jwt.verify(refreshToken, JWT_REFRESH_SECRET, 
    async (err, user) => {
        if(err) {
            return res.status(403).json({success: false, message: "Forbidden: Invalid refresh token"});
        }

        const founduser = await prisma.user.findUnique({
            where: {id: user.userId}
        })

        if(!founduser){
            return res.status(403).json({success: false, message: "Forbidden: User not found"});
    
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