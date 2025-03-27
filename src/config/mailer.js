import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

const transporter = nodemailer.createTransport({
	service: 'gmail',
	auth: {
		user: process.env.EMAIL_USER,
		pass: process.env.EMAIL_PASS,
	},
});

export const sendOTP = async (email, otp) => {
	await transporter.sendMail({
		from: process.env.EMAIL_USER,
		to: email,
		subject: 'Your OTP Code',
		text: `Your OTP code is: ${otp}`,
	});
};

export const sendResetLink = async (email, resetLink) => {
	await transporter.sendMail({
		from: process.env.EMAIL_USER,
		to: email,
		subject: 'Reset Password',
		text: `Click this link to reset your password: ${resetLink}`,
	});
};
