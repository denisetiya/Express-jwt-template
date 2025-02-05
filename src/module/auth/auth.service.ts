import jwt from 'jsonwebtoken';
import prisma from '../../config/prisma.config';
import bcrypt from 'bcrypt'
import dotenv from 'dotenv';
import { iLogin, iRegister } from '../../types/auth';
import isError from '../../utils/handle.error';
import sendEmail from '../../utils/mailer';
dotenv.config();

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET as string;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET as string;



export default class AuthService {
    static async createNewUserByEmail(userData: iRegister) {
        try {

            const existingUser = await prisma.user.findUnique({ where: { email: userData.email } });
            if (existingUser) {
                return {
                    error : "User already exists",
                    status : 409
                }
            }
            const min = 100000;
            const max = 999999;
            const code = Math.floor(Math.random() * (max - min + 1)) + min;
            const validateEmail = await sendEmail(userData.email, "Verify Your Email Address", code.toString(), userData.email);


            if (!validateEmail) {
                return {
                    error : "Failed to send email",
                    status : 500
                }
            }

            console.log(validateEmail);

            const hashedPassword = await bcrypt.hash(userData.password, 10);
            
            const user = await prisma.user.create({
                data: {
                    email: userData.email,
                    password: hashedPassword,
                    activationCode : String(code),
                }, select: {
                    email: true,
                    role : true
                }
            });

            return {
                data : user,
                message : "Verify your email",
                status : 200
            }
        } catch (error) {
            console.error("Error creating user:", error);
            throw new Error("Error creating user");
        }
    }

    static async login(userData:iLogin) {
        try {
            const user = await prisma.user.findUnique(
                { where: { email: userData.email } });
            if (!user) {
                return{
                    error : "Invalid email or password",
                    status : 404
                }  

            }

            if ( !user.activated){
                return {
                    error : "Email not verified, please check your email",
                    status : 401
                }
            };

            const isPasswordValid = await bcrypt.compare(userData.password, user.password);
            if (!isPasswordValid) {
                return {
                    error : "Invalid email or password",
                    status : 401
                }
            }
            const newTokens = await generateTokens(user.id, user.email);

            return  {
                data : {
                    user : {
                        email : user.email,
                        role : user.role
                    },
                    tokens : newTokens
                }
            } 
        } catch (error : unknown) {
            console.error("Error logging in:", error);
            isError(error);
        }
    }

    static async activateEmail(email: string, code: string) {
        try {
            const user = await prisma.user.findUnique({ where: { email } });
            if (!user) {
                return {
                    error : "User not found",
                    status : 404
                }
            }
            if (user.activated) {
                return {
                    error : "User already aktivated",
                    status : 409
                }
            }

            if (user.activationCode !== code) {
                return {
                    error : "Invalid activation code",
                    status : 400
                }
            }

            await prisma.user.update({
                where: { email },
                data: { activated: true },
            })

            return {
                data : {
                   email : user.email,
                    role : user.role
                },
                message : "Email aktivated",
                status : 200
            }
        } catch (error: unknown) {
            console.error("Error activating email:", error);
            isError(error);
        }
    }
}


const generateTokens = async (userId: string, email: string) => {
    try {
        // Generate access and refresh tokens
        const accessToken = jwt.sign({ id: userId, email }, ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
        const refreshToken = jwt.sign({ id: userId, email }, REFRESH_TOKEN_SECRET, { expiresIn: "7d" });

        // Check if the user exists in the database
        const user = await prisma.user.findUnique({ where: { id: userId } });

        // If user doesn't exist, create a new user and store refreshToken
        if (!user) {
            return  {
                status : 404,
                error : "User not found"

            }
        }

        return { accessToken, refreshToken };

    } catch (error) {
        console.error("Error generating tokens:", error);
        throw new Error("Error generating tokens");
    }
};
