import { Router } from 'express';
import { protectedRoute } from '../controllers/protectedController';
import { authorize } from '../middleware/authMiddleware';

const router = Router();

// Protected route (accessible only to users with the 'admin' role)
router.get('/admin', authorize(['admin']), protectedRoute);

export default router;
