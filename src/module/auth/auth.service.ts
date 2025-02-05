import jwt from 'jsonwebtoken';
import prisma from '../../config/prisma.config';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import { iLogin, iRegister } from '../../types/auth';
import throwError from '../../utils/handle.error';
import sendEmail from '../../utils/mailer';
dotenv.config();

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET as string;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET as string;

export default class AuthService {
    static async createNewUserByEmail(userData: iRegister) {
        try {
            // Mengecek apakah pengguna sudah ada
            const existingUser = await prisma.user.findUnique({ where: { email: userData.email } });
            if (existingUser) {
                return {
                    error: "User already exists",
                    status: 409
                };
            }

            // Membuat kode aktivasi
            const min = 100000;
            const max = 999999;
            const code = Math.floor(Math.random() * (max - min + 1)) + min;

            // Mengirim email untuk verifikasi
            const validateEmail = await sendEmail(userData.email, "Verify Your Email Address", code.toString(), userData.email);
            if (!validateEmail) {
                return {
                    error: "Failed to send email",
                    status: 500
                };
            }

            // Mengenkripsi password
            const hashedPassword = await bcrypt.hash(userData.password, 10);

            // Membuat pengguna baru
            const user = await prisma.user.create({
                data: {
                    email: userData.email,
                    password: hashedPassword,
                    activationCode: String(code),
                },
                select: {
                    email: true,
                    role: true
                }
            });

            return {
                data: user,
                message: "Verify your email",
                status: 200
            };
        } catch (error) {
            console.error("Error creating user:", error);
            throwError(error);
        }
    }

    static async login(userData: iLogin) {
        try {
            // Mencari pengguna berdasarkan email
            const user = await prisma.user.findUnique({ where: { email: userData.email } });
            if (!user || !user.activated) {
                return {
                    error: "Invalid email or password",
                    status: 401
                };
            }

            // Memeriksa kecocokan password
            const isPasswordValid = await bcrypt.compare(userData.password, user.password);
            if (!isPasswordValid) {
                return {
                    error: "Invalid email or password",
                    status: 401
                };
            }

            // Menghasilkan token
            const newTokens = await generateTokens(user.id, user.email);

            return {
                data: {
                    user: {
                        email: user.email,
                        role: user.role
                    },
                    tokens: newTokens
                }
            };
        } catch (error: unknown) {
            console.error("Error logging in:", error);
            throwError(error);
        }
    }

    static async activateEmail(email: string, code: string) {
        try {
            const user = await prisma.user.findUnique({ where: { email } });
            if (!user) {
                return {
                    error: "User not found",
                    status: 404
                };
            }

            if (user.activated) {
                return {
                    error: "User already activated",
                    status: 409
                };
            }

            if (user.activationCode !== code) {
                return {
                    error: "Invalid activation code",
                    status: 400
                };
            }

            // Mengupdate status aktivasi
            await prisma.user.update({
                where: { email },
                data: { activated: true },
            });

            return {
                data: {
                    email: user.email,
                    role: user.role
                },
                message: "Email activated",
                status: 200
            };
        } catch (error: unknown) {
            console.error("Error activating email:", error);
            throwError(error);
        }
    }
}

// Fungsi untuk menghasilkan token akses dan refresh
const generateTokens = async (userId: string, email: string) => {
    try {
        // Mencari pengguna berdasarkan email
        const user = await prisma.user.findUnique({
            where: { email },
            include: { tokenRef: true }
        });

        if (!user) {
            return {
                status: 404,
                error: "User not found"
            };
        }

        // Menghasilkan refresh token
        const refreshToken = jwt.sign({ id: user.id, email: user.email }, REFRESH_TOKEN_SECRET, { expiresIn: "7d" });

        // Memperbarui atau membuat refresh token
        if (!user.tokenRef) {
            await prisma.user.update({
                where: { email },
                data: {
                    tokenRef: {
                        create: { refreshToken }
                    }
                }
            });
        } else {
            await prisma.token.update({
                where: { userId: user.id },
                data: { refreshToken }
            });
        }

        // Menghasilkan access token
        const accessToken = jwt.sign({ id: user.id, email: user.email }, ACCESS_TOKEN_SECRET, { expiresIn: "15m" });

        return { accessToken, refreshToken };
    } catch (error : unknown) {
        console.error("Error generating tokens:", error);
        throwError(error);
    }
};
