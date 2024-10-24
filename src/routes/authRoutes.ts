import { Router } from 'express';
import {  login, register } from '../controllers/authController';

const router = Router();

// Login route
router.post('/login', login);

// Register route
router.post('/register', register);

export default router;
