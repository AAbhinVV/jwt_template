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

export { loginSchema, registerSchema };