import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import response from "../utils/response.api";
import prisma from "../config/prisma.config";
import dotenv from "dotenv";

dotenv.config();


const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET as string;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET as string;


export const authenticateJWT = async (req: Request, res: Response, next: NextFunction) => {

    if (req.path.startsWith("/auth")) {
        return next();
    }

    try {
        const authHeader = req.headers.authorization;
        const token = authHeader?.split(" ")[1] || req.cookies?.accessToken;

        if (!token) {
            console.log("Access token not provided.");
            return response(res, 401, "Unauthorized" ,"Access token not provided.");
        }

        jwt.verify(token, ACCESS_TOKEN_SECRET, async (err: any) => {
            if (err) {

                const refreshToken = req.headers["x-refresh-token"] || req.cookies?.refreshToken;

                if (!refreshToken) {
                    return response(res, 401,"Unauthorized," ,"Refresh token not provided and access token invalid or expired.");
                }

                const storedToken = await prisma.token.findUnique({ where: { refreshToken } });
                if (!storedToken) {
                    return response(res, 403,"Forbidden", "Refresh token not found.");
                }

                jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, async (err: any, decodedUser: any) => {
                    if (err) {
                        return response(res, 403,"Forbidden", "Refresh token invalid or expired.");
                    }

                    const newAccessToken = jwt.sign(
                        { id: decodedUser.id, email: decodedUser.email },
                        ACCESS_TOKEN_SECRET,
                        { expiresIn: "15m" }
                    );

                    const newRefreshToken = jwt.sign(
                        { id: decodedUser.id, email: decodedUser.email },
                        REFRESH_TOKEN_SECRET,
                        { expiresIn: "7d" }
                    );

                    await prisma.token.update({
                        where: { id: storedToken.id },
                        data: { refreshToken: newRefreshToken },
                    });

                    res.setHeader("Authorization", `Bearer ${newAccessToken}`);
                    res.cookie("accessToken", newAccessToken, { httpOnly: true });
                    res.cookie("refreshToken", newRefreshToken, { httpOnly: true });
                    return next();
                });
            } else {
                // Jika access token valid, lanjutkan
                return next();
            }
        });
    } catch (error) {
        console.error("Unexpected error in authentication middleware:", error);
        return response(res, 500, "Internal Server Error");
    }
};