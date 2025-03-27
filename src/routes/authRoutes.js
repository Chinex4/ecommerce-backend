import express from 'express';
import {
	register,
	verifyOTP,
	login,
	forgotPassword,
    logout,
} from '../controllers/authController.js';
const router = express.Router();

router.post('/signup', register);
router.post('/verify-otp', verifyOTP);
router.post('/login', login);
router.post('/logout', logout);
router.post('/forgot-password', forgotPassword);

export default router;
