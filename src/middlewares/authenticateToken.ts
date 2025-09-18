import express from 'express'
import { ApiError } from '../errors/ApiError';
import jwt from 'jsonwebtoken'
import { error } from 'console';
import { decode } from 'punycode';

export const authenticateToken = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            throw new ApiError(401, 'Access token not found');
        }

        jwt.verify(
            token,
            process.env.ACCESS_TOKEN_SECRET!,
            (error,decoded) => {
                if (error) {
                    if (error instanceof jwt.TokenExpiredError) {
                        throw new ApiError(401, 'Access token expired');
                    } else if (error instanceof jwt.JsonWebTokenError) {
                        throw new ApiError(403, 'Invalid access token');
                    } else {
                        throw new ApiError(401, 'Error verifying access token');
                    }
                }
                if (!decoded || typeof decoded === 'string') {
                    throw new ApiError(500, 'Access token Payload error');
                }
                next();
            }
        )
    } catch (error) {
        next(error);
    }
}