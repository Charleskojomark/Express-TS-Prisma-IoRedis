import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import dotenv from "dotenv";

dotenv.config();

const SECRET_KEY = process.env.SECRET_KEY || 'oASVUyg1cPzbKglgjMIetErJOEhA';

interface DecodedToken {
  username: string;
  password: string;
  role: string;
}

// Extend Request interface to include user property
declare global {
  namespace Express {
    interface Request {
      user?: DecodedToken;
    }
  }
}

export const authorize = (allowedRoles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
      return res.status(403).json({ message: 'No token provided' }) as any;
    }

    const token = authHeader.split(' ')[1];

    try {
      const decoded = jwt.verify(token, SECRET_KEY) as DecodedToken;

      if (!allowedRoles.includes(decoded.role)) {
        return res.status(403).json({ message: 'Access denied' }) as any;
      }

      req.user = decoded;  // Now TypeScript recognizes req.user
      next();
    } catch (error) {
      console.error('Token verification error:', error);
      return res.status(401).json({ message: 'Invalid token' }) as any;
    }
  };
};
