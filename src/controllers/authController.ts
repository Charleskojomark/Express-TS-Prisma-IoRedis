import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import prisma from '../prisma/prismaClient'; // Adjust the path as needed
import jwt from 'jsonwebtoken';
import dotenv from "dotenv";
import redis from '../redisClient'; // Import redis client

dotenv.config();

const SECRET_KEY = process.env.SECRET_KEY || 'oASVUyg1cPzbKglgjMIetErJOEhA';

// Login controller
export const login = async (req: Request, res: Response): Promise<any> => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  // Check if the user exists in Redis cache
  const cachedUser = await redis.get(`user:${username}`);
  let user;

  if (cachedUser) {
    user = JSON.parse(cachedUser);
  } else {
    // Find the user in the database if not found in Redis
    user = await prisma.users.findUnique({
      where: { username },
    });

    // Cache the user data in Redis
    if (user) {
      await redis.set(`user:${username}`, JSON.stringify(user), 'EX', 3600); // Cache for 1 hour
    }
  }

  // Check if user exists and password is correct
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Generate JWT
  const token = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

  // Cache the JWT token in Redis for session management
  await redis.set(`token:${username}`, token, 'EX', 3600); // Token expires in 1 hour

  return res.json({ token });
};

// Register controller
export const register = async (req: Request, res: Response): Promise<any> => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  if (!role) {
    return res.status(400).json({ message: 'Role is required' });
  }

  // Check if the user already exists
  const existingUser = await prisma.users.findUnique({
    where: { username },
  });

  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }

  // Hash the password and create the new user
  const hashedPassword = bcrypt.hashSync(password, 8);

  const newUser = await prisma.users.create({
    data: {
      username,
      password: hashedPassword,
      role,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  });

  // Cache the new user in Redis
  await redis.set(`user:${newUser.username}`, JSON.stringify(newUser), 'EX', 3600); // Cache for 1 hour

  return res.status(201).json({ message: 'User registered successfully' });
};
