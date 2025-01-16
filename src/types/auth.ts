import {z} from 'zod';

export const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8).refine(
        (val) => {
            const hasUpperCase = /[A-Z]/.test(val);
            const hasLowerCase = /[a-z]/.test(val);
            const hasNumber = /[0-9]/.test(val);
            const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(val);

            return hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar;
        },
        {
            message: "Password should contain at least one uppercase letter, one lowercase letter, one number, and one special character"
        }
    )
})


export const loginSchema = z.object({
    email: z.string().email(),
    password : z.string()
})

export type iLogin = z.infer<typeof loginSchema>
export type iRegister = z.infer<typeof registerSchema>