import express, { Request, Response } from "express";
import response from "../../utils/response.api";
import admin from "../../config/firbase-admin.conf";
import { generateTokens, createNewUser } from "./auth.service";

const auth = express();

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


//  auth manualy

auth.post("/auth", async(req: Request, res: Response) => {
    const {email, password} : {email: string, password: string} = req.body;

    if (!email || !password) {
        return response(res, 400, "Bad Request", "Email and password are required");
    }
    try {
        const user = await createNewUser(email, password); 

        if (!user) {
            return response(res, 401, "Unauthorized", "User not found");
        }

        const tokens = await generateTokens(user.id, user.email);
        if (!tokens) {
            return response(res, 401, "Unauthorized", "Tokens not found");
        }
        
        return response(res, 200, "Success",null, tokens);
    } catch (error) {
        return response(res, 401, "Unauthorized", error);
    }
})

export default auth