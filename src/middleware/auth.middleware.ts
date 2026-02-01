import jwt from "jsonwebtoken";
import prisma from "../config/prisma.js";
import type { Request, Response, NextFunction,  } from "express";
import env from "../config/env.js";


interface JWTPayloadWithUserId extends jwt.JwtPayload {
    userId: string;
}

const useAuth = async (req : Request, res : Response, next : NextFunction) : Promise<void> => {
    try{
        const authHeader = req.headers.authorization;
        const token = req.cookies?.accessToken || req.signedCookies?.accessToken||(authHeader?.startsWith('Bearer ') ?  authHeader.split(" ")[1] : undefined);

        if (!token) {
            res.status(401).json({ success: false, message: "Access token missing" });
            return;
        }


        const decoded = jwt.verify(token, env.JWT_ACCESS_SECRET) as JWTPayloadWithUserId;

        if(!decoded?.userId){
            res.status(401).json({success: false, message: "Invalid Access token"});
            return
        }

        const user  = await prisma.user.findUnique({
            where: {id: decoded.userId},
            omit: {password: true}
        })

        if(!user){
            res.status(401).json({success: false, message: "No user with this id"});
        }

        req.user = user;


        next();
    } catch (error : unknown) {
        if (error instanceof Error){
            console.log(error.message)
        }else{
            console.log("Invalid Token")
        }

        res.sendStatus(403);

        // console.log((error as Error).message || "Invalid token");
        // res.sendStatus(503);
    }
}

export default useAuth;