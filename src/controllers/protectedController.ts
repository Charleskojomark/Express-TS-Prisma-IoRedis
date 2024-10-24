import { Request, Response } from 'express';

export const protectedRoute = (req: Request, res: Response) => {
  res.json({ message: 'This is a protected route. Only accessible with valid token and proper role.' });
};
