import jwt from 'jsonwebtoken';
import prisma from '../../config/prisma.config';
import bcrypt from 'bcrypt'
import dotenv from 'dotenv';
dotenv.config();

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET as string;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET as string;

export const createNewUser = async (email: string, password: string) => {
    try {
        const hashedPassword = await bcrypt.hash(password, 50);
        const userId = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

        const user = await prisma.user.create({
            data: {
                id: userId,
                email: email,
                password: hashedPassword
            } 
        });
        return user;
    } catch (error) {
        throw new Error("Error creating user");
    }
}


export const generateTokens = async (userId: string, email: string) => {
    try {
        // Generate access and refresh tokens
        const accessToken = jwt.sign({ id: userId, email }, ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
        const refreshToken = jwt.sign({ id: userId, email }, REFRESH_TOKEN_SECRET, { expiresIn: "7d" });

        // Check if the user exists in the database
        const user = await prisma.user.findUnique({ where: { id: userId } });

        // If user doesn't exist, create a new user and store refreshToken
        if (!user) {
            return "User not found";
        }

        return { accessToken, refreshToken };

    } catch (error) {
        console.error("Error generating tokens:", error);
        throw new Error("Error generating tokens");
    }
};
