import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

export const protect = (req, res, next) => {
	const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];

	if (!token) return res.status(401).json({ message: 'Unauthorized' });

	try {
		const decoded = jwt.verify(token, process.env.JWT_SECRET);
		req.user = decoded;

		// Check if the token has expired (1 hour session)
		if (Date.now() >= decoded.exp * 1000) {
			res.clearCookie('token'); // Clear expired token
			return res.status(401).json({ message: 'Session expired. Please log in again.' });
		}

		next();
	} catch (error) {
		res.status(401).json({ message: 'Invalid token' });
	}
};

export const isAdmin = (req, res, next) => {
	if (req.user.role !== 'ADMIN')
		return res.status(403).json({ message: 'Access denied' });
	next();
};
