import * as z from "zod";

const loginSchema = z.object({
    email: z.email("Invalid email address"),
    password: z.string().regex(/((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{8,64})/g, "Password must be 8-64 characters and include at least one uppercase letter, one lowercase letter, one number, and one special character"),
})

const registerSchema = z.object({
    fullName: z.string().min(2, "fullName must be at least 2 characters long").max(100, "fullName must be at most 100 characters long"),
    lastName: z.string().min(2, "lastName must be at least 2 characters long").max(100, "lastName must be at most 100 characters long"),
    email: z.email("Invalid email address"),
    password: z.string().regex(/((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{8,64})/g, "Password must be 8-64 characters and include at least one uppercase letter, one lowercase letter, one number, and one special character"),
})

const envSchema = z.object({
    PORT: z.coerce.number().default(4000),
    DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
    JWT_ACCESS_SECRET: z.string().min(1),
    JWT_REFRESH_SECRET: z.string().min(1),
    ACCESS_TOKEN_EXPIRY: z.string().min(1),
    REFRESH_TOKEN_EXPIRY : z.string().min(1),
    REDIS_URL: z.string().min(1),
})

const env = envSchema.parse(process.env);

export { loginSchema, registerSchema, env };