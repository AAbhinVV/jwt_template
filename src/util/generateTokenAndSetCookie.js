import jwt from 'jsonwebtoken';
import { JWT_ACCESS_SECRET, ACCESS_TOKEN_EXPIRY, JWT_REFRESH_SECRET, REFRESH_TOKEN_EXPIRY } from '../config/jwtConfig.js';
import { redisClient } from '../config/redis.js';

export const generateTokenAndSetCookie = async (res, userId) => {
    const accessToken = jwt.sign({ userId}, JWT_ACCESS_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ userId}, JWT_REFRESH_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

    if(!accessToken || !refreshToken) {
        throw new Error('Token generation failed');
    }

    const refreshTokenKey = `refreshToken:${userId}`;

    await redisClient.set(refreshTokenKey, refreshToken, {EX: REFRESH_TOKEN_EXPIRY});

    // res.cookie("accessToken", accessToken, {
    //     signed: true,
    //     httpOnly: true,
    //     secure: process.env.NODE_ENV === 'production',
    //     sameSite: 'Strict',
    //     maxAge: parseExpiryToMillis(ACCESS_TOKEN_EXPIRY)
    // });

    res.cookie("refreshToken", refreshToken, {
        signed: true,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
        maxAge: parseExpiryToMillis(REFRESH_TOKEN_EXPIRY)
    });

    return { accessToken, refreshToken };
};


export const verifyRefreshToken = async (token) => {
    try {
        const decoded = jwt.verify(token, JWT_REFRESH_SECRET);  

        const storedToken = await redisClient.get(`refreshToken:${decoded.userId}`);

        if(storedToken !== token) {
            return decoded;
        }

        return null;
    } catch (error) {
        return error;
    }
};

export const generateAccessToken = (userId) => {
    const accessToken = jwt.sign({ userId }, JWT_ACCESS_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
    return accessToken;
}
