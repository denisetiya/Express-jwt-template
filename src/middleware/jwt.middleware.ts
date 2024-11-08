import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import response from "../utils/response.api";
import prisma from "../config/prisma.config";
import dotenv from "dotenv";

dotenv.config();

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET as string;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET as string;

export const authenticateJWT = async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    if (req.path.startsWith("/auth")) {
        return next();
    }

    if (authHeader) {
        const token = authHeader.split(" ")[1];

        if (token) {
            jwt.verify(token, ACCESS_TOKEN_SECRET, async (err) => {
                if (err) {
                    const refreshToken = req.headers["x-refresh-token"] || req.body.refreshToken;
                    if (!refreshToken) {
                        return response(res, 401, "Unauthorized", err);
                    }
    
                    const storedToken = await prisma.user.findFirst({ where: { refreshToken: refreshToken }});
    
                    if (!storedToken) return response(res, 403, "Forbidden");
    
                    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err: any, decodedUser: any) => {
                        if (err) return response(res, 403, "Forbidden",err);
    
                        // Buat token akses baru dan tambahkan ke header respons
                        const newAccessToken = jwt.sign(
                            { id: decodedUser.id, email: decodedUser.email },
                            ACCESS_TOKEN_SECRET,
                            { expiresIn: "15m" }
                        );
                        // Mengirim token baru melalui header respons
                        res.setHeader("Authorization", `Bearer ${newAccessToken}`);
                        next();
                    });
                } else {
                    // Token valid, lanjutkan ke route berikutnya tanpa menyimpan user ke req.user
                    next();
                }
            });
        } else {
           return response(res, 401, "Unauthorized");
        }
    } else {
        return response(res, 401, "Unauthorized");
    }
};
