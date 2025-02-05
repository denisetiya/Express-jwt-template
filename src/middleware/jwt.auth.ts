import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import response from "../utils/response.api";
import prisma from "../config/prisma.config";
import dotenv from "dotenv";

dotenv.config();

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET as string;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET as string;

// Function to verify JWT token
const verifyToken = (token: string, secret: string) => {
    return new Promise<any>((resolve, reject) => {
        jwt.verify(token, secret, (err, decoded) => {
            if (err) {
                reject(err);
            } else {
                resolve(decoded);
            }
        });
    });
};

// Function to generate a new token
const generateNewToken = (user: any, secret: string, expiresIn: string) => {
    return jwt.sign(
        { id: user.id, email: user.email },
        secret,
        { expiresIn }
    );
};

// Function to handle refreshing token logic
const handleRefreshToken = async (refreshToken: string, res: Response) => {
    const storedToken = await prisma.token.findUnique({ where: { refreshToken } });
    if (!storedToken) {
        return response(res, 403, "Forbidden", "Refresh token not found or invalid.");
    }

    try {
        const decodedUser = await verifyToken(refreshToken, REFRESH_TOKEN_SECRET);

        const newAccessToken = generateNewToken(decodedUser, ACCESS_TOKEN_SECRET, "15m");
        const newRefreshToken = generateNewToken(decodedUser, REFRESH_TOKEN_SECRET, "7d");

        await prisma.token.update({
            where: { id: storedToken.id },
            data: { refreshToken: newRefreshToken },
        });

        return { newAccessToken, newRefreshToken };
    } catch (err) {
        return response(res, 403, "Forbidden", "Refresh token invalid or expired.");
    }
};




// =================================== main ============================================== //

export const authenticateJWT = async (req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith("/auth")) {
        return next();
    }

    const token = req.headers.authorization?.split(" ")[1] || req.cookies?.accessToken;

    if (!token) {
        return response(res, 401, "Unauthorized", "Access token not provided.");
    }

    try {
        // Attempt to verify the access token
        try {
            await verifyToken(token, ACCESS_TOKEN_SECRET);
            return next();
        } catch (err) {
            // If access token is expired or invalid, try refreshing it
            const refreshToken = req.headers["x-refresh-token"] || req.cookies?.refreshToken;

            if (!refreshToken) {
                return response(res, 401, "Unauthorized", "Refresh token not provided and access token invalid or expired.");
            }

            const tokenData = await handleRefreshToken(refreshToken, res);
            if (tokenData) {
                res.setHeader("Authorization", `Bearer ${tokenData.newAccessToken}`);
                res.cookie("accessToken", tokenData.newAccessToken, { httpOnly: true });
                res.cookie("refreshToken", tokenData.newRefreshToken, { httpOnly: true });
                return next();
            }
        }
    } catch (error) {
        console.error("Unexpected error in authentication middleware:", error);
        return response(res, 500, "Internal Server Error");
    }
};
