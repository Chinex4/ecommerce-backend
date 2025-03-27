import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import authRoutes from './src/routes/authRoutes.js';
import dashboardRoutes from './src/routes/dashboard.js';
import cookieParser from 'cookie-parser';


dotenv.config();
const app = express();

app.use(cors({
	origin: process.env.FRONTEND_URL, // Allow frontend requests
	credentials: true, // Allow sending cookies
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // ✅ Enables cookie parsing

app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);

app.listen(5000, () => console.log('Server running on port 5000'));
