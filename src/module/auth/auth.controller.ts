import  { Router,Request, Response } from "express";
import response from "../../utils/response.api";
// import admin from "../../config/firbase-admin.conf";
import AuthService from "./auth.service";
import { iLogin, loginSchema, registerSchema, iRegister } from "../../types/auth";
const auth: Router = Router();


//  auth with firebase

// auth.post("/auth", async(req: Request, res: Response) => {
//     const tokenFirebase = req.headers.authorization;

//     if (!tokenFirebase) {
//         return response(res, 401, "Unauthorized", "Token not found");
//     }
//     const token = tokenFirebase?.split(" ")[1];
    
//     try {
//         const user = await admin.auth().verifyIdToken(token as string);
//         const tokens = await generateTokens(user.uid, user.email as string);

//         return response(res, 200, "Success",null, tokens);

//     } catch (error) {
//         return response(res, 401, "Unauthorized", error);
//     }



// });




auth.post("/auth/register", async(req: Request, res: Response) => {
    const userData :iRegister = req.body;
    const validateData = registerSchema.safeParse(userData);

    if (!validateData.success) {
        const errors = validateData.error.errors.map(err => ({
            path: err.path.join('.'),
            message: err.message
        }));
        return response(res, 400, "Bad Request", errors);
    }

    try {


        const newUser = await AuthService.createNewUserByEmail(userData);

        if (!newUser?.data) {
            return response(res, newUser?.status as number, "failed register", newUser?.error);
        }

        return response(res, 200, newUser?.message, null, newUser?.data, {
            guide : "next you can verify this account, in route `auth/verify/:email/:code`, or klik activated in email",
        });

    } catch (error:any) {
        return response(res, error.status, 'failed register',  error.message,);
    }
})

auth.post("/auth/login", async(req: Request, res: Response) => {
    const userData :iLogin = req.body;

    const validateData = loginSchema.safeParse(userData);

    if (!validateData.success) {
        const errors = validateData.error.errors.map(err => ({
            path: err.path.join('.'),
            message: err.message
        }));
        return response(res, 400, "Bad Request", errors);
    }

    try {
        const user = await AuthService.login(userData); 

        if (!user?.data) {
            return response(res, user?.status as number, "failed login", user?.error);
        }
        res.cookie("accessToken", user.data.tokens?.accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production" ? true : false,
            sameSite: "none",
            maxAge: 15 * 60 * 1000
        })

        res.cookie("refreshToken", user.data.tokens?.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production" ? true : false,
            sameSite: "none",
            maxAge: 7 * 24 * 60 * 60 * 1000
        })
        return response(res, 200, "Success", null, user?.data.user, user?.data.tokens);

    } catch (error:any) {
        return response(res, error.status, 'failed login',  error.message,);
    }
})


auth.post("/auth/verify/:email/:code", async(req: Request, res: Response) => {
    const email = req.params.email;
    const code = req.params.code;

    try {
        const user = await AuthService.activateEmail(email as string, code as string);

        if (!user?.data) {
            return response(res, user?.status as number, "failed aktivated", user?.error);
        }
        return response(res, 200, "Success", null, user?.data);
    } catch (error:any) {
        return response(res, error.status, 'failed aktivated',  error.message,);
    }
})

export default auth

