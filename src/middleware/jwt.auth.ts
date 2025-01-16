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
        const token = authHeader.split(" ")[1] ||  req.cookies.accessToken;

        if (token) {
            jwt.verify(token, ACCESS_TOKEN_SECRET, async (err: any) => {
                if (err) {
                    const refreshToken = req.headers["x-refresh-token"] || req.cookies.refreshToken;
                    if (!refreshToken) {
                        return response(res, 401, "Unauthorized", err);
                    }
    
                    const storedToken = await prisma.token.findUnique({ where: { refreshToken: refreshToken }});
    
                    if (!storedToken) return response(res, 403, "Forbidden");
    
                    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err: any, decodedUser: any) => {
                        if (err) return response(res, 403, "Forbidden",err);
    
                        // Buat token akses baru dan tambahkan ke header respons
                        const newAccessToken = jwt.sign(
                            { id: decodedUser.id, email: decodedUser.email },
                            ACCESS_TOKEN_SECRET,
                            { expiresIn: "15m" }
                        );

                        const newRefreshToken = jwt.sign(
                            { id: decodedUser.id, email: decodedUser.email },
                            REFRESH_TOKEN_SECRET,
                            { expiresIn: "7d" }
                        )

                        prisma.token.update({
                            where: {
                                id: storedToken.id
                            },
                            data: {
                                refreshToken: newRefreshToken
                            }
                        })
                        res.cookie("accessToken", newAccessToken, {
                            httpOnly: true,
                            secure: true,
                            sameSite: "none",
                            maxAge: 15 * 60 * 1000
                        })

                        res.cookie("refreshToken", newRefreshToken, {
                            httpOnly: true,
                            secure: true,
                            sameSite: "none",
                            maxAge: 7 * 24 * 60 * 60 * 1000
                        })
                        res.setHeader("Authorization", `Bearer ${newAccessToken}`);
                        next();
                    });
                } else {
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