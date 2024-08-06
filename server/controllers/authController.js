const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const transporter = require('../mailConfig');
const PasswordResetToken = require('../models/PasswordReset');

const generateOtp = () => {
  return crypto.randomInt(100000, 999999).toString();
};

exports.register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'User already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOtp();

    const newUser = await User.create({ username, email, password: hashedPassword, otp });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Welcome to Our Service',
      text: `Welcome! Your OTP is ${otp}.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log('Error sending email:', error);
        return res.status(500).json({ error: 'Failed to send welcome email' });
      }

      res.status(201).json({ message: 'User registered successfully, OTP sent to email', user: newUser });
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.verifyOtp = async (req, res) => {
  const { otp, email } = req.body;

  try {
    const user = await User.findOne({ where: { email, otp } });

    if (user) {
      user.otp = null;
      await user.save();
      res.json({ success: true });
    } else {
      res.status(400).json({ success: false, message: 'Invalid OTP' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(400).json({ message: 'User does not exist' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    console.log(`Received password reset request for email: ${email}`);

    const user = await User.findOne({ where: { email } });
    if (!user) {
      console.log('User not found for email:', email);
      return res.json({ message: 'If your email address is found, a reset link will be sent to your email.' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const tokenExpiry = Date.now() + 3600000; // Token expires in 1 hour

    console.log(`Generated reset token: ${token}`);
    console.log(`Hashed reset token: ${hashedToken}`);
    console.log(`Token expiry time: ${new Date(tokenExpiry).toISOString()}`);

    await PasswordResetToken.create({
      userId: user.id,
      token: hashedToken,
      tokenExpiry,
    });

    const resetLink = `http://localhost:3000/reset-password?token=${token}`;
    console.log(`Password reset link: ${resetLink}`);

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Password Reset',
      text: `You requested a password reset. Please use the following link to reset your password: ${resetLink}`,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Password reset email sent to ${user.email}`);

    res.json({ message: 'If your email address is found, a reset link will be sent to your email.' });
  } catch (error) {
    console.error('Error in forgotPassword:', error);
    res.status(500).json({ error: 'Server error.' });
  }
};



exports.resetPassword = async (req, res) => {
  const { newPassword } = req.body;
  const { token } = req.params; 

  try {
    console.log('Token received from client:', token);

    // Hash the token received from the client
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    // console.log('Hashed token:', hashedToken);

    // Find the reset token in the database
    const resetToken = await PasswordResetToken.findOne({ where: { token: hashedToken } });

    if (!resetToken) {
      // console.log('Reset token not found or expired');
      return res.status(400).json({ error: 'Invalid or expired token.' });
    }

    // Check if the token has expired
    if (resetToken.tokenExpiry < Date.now()) {
      // console.log('Token has expired');
      return res.status(400).json({ error: 'Token has expired.' });
    }

    // Find the user associated with the token
    const user = await User.findOne({ where: { id: resetToken.userId } });

    if (!user) {
      console.log('User not found');
      return res.status(400).json({ error: 'User not found.' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password
    user.password = hashedPassword;
    await user.save();

    // Delete the reset token
    await resetToken.destroy();

    res.json({ message: 'Password reset successfully.' });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Server error.' });
  }
};

