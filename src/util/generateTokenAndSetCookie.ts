import jwt from 'jsonwebtoken';
import env from '../config/env.js';
import { redisClient } from '../config/redis.js';
import type { Response } from 'express';


type TokenPair = {
    accessToken : string;
    refreshToken : string;
}

type RefreshTokenPair = {
    userId : string
}


export const generateTokenAndSetCookie = async (res : Response, userId : any) : Promise<TokenPair> => {
    const accessToken = jwt.sign({ userId}, env.JWT_ACCESS_SECRET, { expiresIn: env.ACCESS_TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ userId}, env.JWT_REFRESH_SECRET, { expiresIn: env.REFRESH_TOKEN_EXPIRY });

    if(!accessToken || !refreshToken) {
        throw new Error('Token generation failed');
    }

    const refreshTokenKey = `refreshToken:${userId}`;

    await redisClient.set(refreshTokenKey, refreshToken, {EX : Number(env.REFRESH_TOKEN_EXPIRY)});

    // res.cookie("accessToken", accessToken, {
    //     signed: true,
    //     httpOnly: true,
    //     secure: process.env.NODE_ENV === 'production',
    //     sameSite: 'Strict',
    //     maxAge: parseExpiryToMillis(env.ACCESS_TOKEN_EXPIRY)
    // });

    res.cookie("refreshToken", refreshToken, {
        signed: true,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: parseExpiryToMillis(env.REFRESH_TOKEN_EXPIRY)
    });

    return { accessToken, refreshToken };
};


export const verifyRefreshToken = async (token : string) : Promise<RefreshTokenPair | null> => {
    try {
        const decoded = jwt.verify(token, env.JWT_REFRESH_SECRET) as JwtPayload & { userId : string};  

        const storedToken = await redisClient.get(`refreshToken:${decoded.userId}`);

        if(storedToken !== token) {
            return decoded;
        }

        return {userId : decoded.userId};
    } catch  {
        return null;
    }
};

export const generateAccessToken = (userId : any) => {
    const accessToken = jwt.sign({ userId }, env.JWT_ACCESS_SECRET, { expiresIn: env.ACCESS_TOKEN_EXPIRY });
    return accessToken;
}
