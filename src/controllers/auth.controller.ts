import jwt from 'jsonwebtoken'
import express from 'express'
import bcrypt from 'bcrypt'
import { userModel } from '../models/user'
import { ApiError } from '../errors/ApiError'
import { access } from 'fs'

const createAccessToken = (userId: string) => {
    return jwt.sign(
        {userId},
        process.env.ACCESS_TOKEN_SECRET!,
        {expiresIn: '15m'})
}

const createRefreshToken = (userId: string) => {
    return jwt.sign(
        {userId},
        process.env.REFRESH_TOKEN_SECRET!,
        {expiresIn: '7d'})
}

//user signup
export const createUser = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
        const {
            fullName,
            email,
            password
        } = req.body

        const profileImage = req.file?.path

        const SALT = 10
        const hashedPassword = await bcrypt.hash(password, SALT)

        const user = new userModel({
            fullName,
            email,
            profileImage,
            password: hashedPassword
        })

        await user.save()
        res.status(201).json({message: 'User created successfully'})
    } catch (error) {
        next(error)
    }
}

//user login
export const authenticateUser = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
        const {email , password} = req.body
        const user = await userModel.findOne({email})

        if (!user) {
            throw new ApiError(404, 'User not found')
        }

        const isPasswordValid = await bcrypt.compare(password, user.password)

        if (!isPasswordValid) {
            throw new ApiError(401, 'Invalid password')
        }

        const accessToken = createAccessToken(user._id.toString())
        const refreshToken = createRefreshToken(user._id.toString())

        const isProd = process.env.NODE_ENV === 'production'

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd? "none" : "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/api/auth/refresh-token'
        })

        res.status(200).json({
            message: 'User authenticated successfully',
            accessToken,
            user: {
                fullName: user.fullName,
                email: user.email,
                profileImage: user.profileImage
            }
        })
    } catch (error) {
        next(error)
    }
}

//Refresh token
export const refreshAccessToken = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try{
        const token = req.cookies.refreshToken;

        if (!token) {
            throw new ApiError(401, 'Refresh token not found')
        }

        jwt.verify(
            token,
            process.env.REFRESH_TOKEN_SECRET!,
            async (err: Error | null, decoded: string | jwt.JwtPayload | undefined) => {
                if (err) {
                    if (err instanceof jwt.TokenExpiredError) {
                        throw new ApiError(401, 'Refresh token expired')
                    } else if (err instanceof jwt.JsonWebTokenError) {
                        throw new ApiError(403, 'Invalid refresh token')
                    } else {
                        throw new ApiError(401, 'Error verifying refresh token')
                    }
                }
                if (!decoded || typeof decoded === 'string') {
                    return next(new ApiError(500, 'Refresh token Payload error'))
                }
                const userId = decoded.userId as string

                const user = await userModel.findById(userId)

                if (!user) {
                    return next(new ApiError(404, 'User not found'))
                }

                const newAccessToken = createAccessToken(user._id.toString())

                res.status(200).json({accessToken: newAccessToken})
            }
        )
    }catch (error) {
        next(error)
    }
}

//getallusers
export const getAllUsers = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try{
        const authHeader = req.headers['authorization'];
        if(!authHeader || !authHeader.startsWith('Bearer ')){
            throw new ApiError(401, 'Access token not found');
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!);

        if(!decoded || typeof decoded === 'string'){
            throw new ApiError(500, 'Access token Payload error');
        }

        const users = await userModel.find();
        res.status(200).json({users});
    } catch (error) {
        next(error);
    }
}

//logout user
export const logout = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const isProd = process.env.NODE_ENV === "production"
    try{
        res.clearCookie("refreshToken",{
            httpOnly: true,
            secure: isProd,
            sameSite: "none",
            path: "/api/auth/refresh-token"
        })

        res.status(200).json({
            message: "Logout successful",

        })
    }catch (err) {
        next(err)
    }
}