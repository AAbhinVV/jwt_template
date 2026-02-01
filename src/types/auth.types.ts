interface LoginParams {
    email: string;
    password: string;
    ip: string;
}

interface RegisterParams {
    fullName: string;
    lastName: string;
    email: string;
    password: string;
    ip: string;
}

interface JWTPayloadWithUserId extends jwt.JwtPayload {
    userId: string;
}



export type { LoginParams, RegisterParams };