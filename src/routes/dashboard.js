import express from 'express';
import {
	getUserDashboard,
	getAdminDashboard,
} from '../controllers/authController.js';
import { protect, isAdmin } from '../middlewares/authMiddleware.js'; // Updated imports

const router = express.Router();

// 🟢 User Dashboard - Protected Route
router.get('/user', protect, getUserDashboard);

// 🔴 Admin Dashboard - Protected & Admin-Only Route
router.get('/admin', protect, isAdmin, getAdminDashboard);

export default router;
