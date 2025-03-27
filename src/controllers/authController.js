import bcrypt from 'bcryptjs';
import prisma from '../config/db.js';
import generateToken from '../utils/generateToken.js';
import { generateOTP } from '../utils/generateOTP.js';
import { sendOTP, sendResetLink } from '../config/mailer.js';

export const register = async (req, res) => {
	const { name, email, password } = req.body;

	const userExists = await prisma.user.findUnique({ where: { email } });
	if (userExists)
		return res.status(400).json({ message: 'User already exists' });

	const hashedPassword = await bcrypt.hash(password, 10);
	const otp = generateOTP();

	const user = await prisma.user.create({
		data: {
			name,
			email,
			password: hashedPassword,
			otp,
			otpExpiresAt: new Date(Date.now() + 10 * 60 * 1000),
		},
	});

	await sendOTP(user.email, otp);
	res.status(201).json({ message: 'OTP sent. Verify your email.' });
};

export const verifyOTP = async (req, res) => {
	const { email, otp } = req.body;

	const user = await prisma.user.findUnique({ where: { email } });
	if (!user || user.otp !== otp || new Date() > user.otpExpiresAt)
		return res.status(400).json({ message: 'Invalid or expired OTP' });

	await prisma.user.update({
		where: { email },
		data: { isVerified: true, otp: null, otpExpiresAt: null },
	});

	res.json({ message: 'Email verified. Proceed to login.' });
};

export const login = async (req, res) => {
	const { email, password } = req.body;

	const user = await prisma.user.findUnique({ where: { email } });
	if (!user || !user.isVerified)
		return res.status(400).json({ message: 'User not found or not verified' });

	const isMatch = await bcrypt.compare(password, user.password);
	if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

	// Generate token with a 1-hour expiry time
	const token = generateToken(user.id, user.role, '1h');

	// Set the token in cookies for session management
	res.cookie('token', token, {
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production',
		maxAge: 3600000, // 1 hour in milliseconds
	});
	res.json({ token, role: user.role });
};

export const logout = (req, res) => {
	// Clear the token from cookies
	res.clearCookie('token');
	res.json({ message: 'Logged out successfully' });
};

export const forgotPassword = async (req, res) => {
	const { email } = req.body;
	const user = await prisma.user.findUnique({ where: { email } });

	if (!user) return res.status(400).json({ message: 'User does not exist' });

	const resetToken = generateToken(user.id, user.role);
	const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

	await sendResetLink(email, resetLink);
	res.json({ message: 'Password reset link sent to email' });
};

// 🟢 GET User Dashboard (Authenticated User)
export const getUserDashboard = async (req, res) => {
	try {
		const user = await prisma.user.findUnique({
			where: { id: req.user.id },
			select: { id: true, name: true, email: true, role: true }, // Exclude sensitive data
		});

		if (!user) return res.status(404).json({ message: 'User not found' });

		res.json(user);
	} catch (error) {
		console.error(error);
		res.status(500).json({ message: 'Server error' });
	}
};

// 🔴 GET Admin Dashboard (List all Users)
export const getAdminDashboard = async (req, res) => {
	// try {
	// 	if (req.user.role !== 'ADMIN')
	// 		return res.status(403).json({ message: 'Access denied: Admins only' });

	// 	const admins = await prisma.user.findMany({
	// 		select: { id: true, name: true, email: true, role: true },
	// 	});

	// 	res.json(admins);
	// } catch (error) {
	// 	console.error(error);
	// 	res.status(500).json({ message: 'Server error' });
	// }

	try {
		const admin = await prisma.user.findUnique({
			where: { id: req.user.id, role: 'ADMIN' },
		});

		if (!admin) return res.status(403).json({ message: 'Access denied' });

		res.json({ message: 'Welcome Admin!', admin });
	} catch (error) {
		console.error(error);
		res.status(500).json({ message: 'Server error' });
	}
};
