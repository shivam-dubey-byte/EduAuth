const { createUser, findUserByEmail, comparePassword,findUserById, updatePassword } = require('../models/userModel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const { sendResetEmail } = require('../mail/resetMail');

// User Signup
const signup = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user already exists
    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Create new user
    const userId = await createUser(email, password);
    res.status(201).json({ message: 'User signed up successfully', userId });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
};

// User Login
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user in DB
    const users = await findUserByEmail(email);
    if (!users) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare passwords
    const isMatch = await comparePassword(password, users.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT Token
    const token = jwt.sign({ userId: users._id, email: users.email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
};

// Forgot Password Controller
const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
      // Check if the user exists
      const user = await findUserByEmail(email); 
      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      // Generate a reset token
      const resetToken = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET, {expiresIn: '1h',});

      // Save the reset token and expiration in the database
      //user.resetPasswordToken = resetToken;
      //user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
      //await user.save();

      // Send the reset token via email
      const resetUrl = `https://knowledgesun.quantumsoftdev.in/reset-password/${resetToken}`;
      await sendResetEmail(user.email, resetUrl);

      res.status(200).json({ message: 'Password reset email sent' });
  } catch (error) {
      res.status(500).json({ message: 'Server error', error });
  }
};

// Reset Password Controller
const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    console.log(token);
      // Verify the token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log(decoded);
      const {id,email,iat,exp} = decoded;

      // Find the user
      const user = await findUserByEmail(email); 
      console.log(user);

      if (!user) {
          return res.status(400).json({ message: 'Invalid or expired token' });
      }
      await updatePassword(user._id,newPassword );
      res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
      res.status(500).json({ message: 'Server error', error });
  }
};

module.exports = { signup, login, forgotPassword, resetPassword};
