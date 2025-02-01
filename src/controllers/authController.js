const { createUser, findUserByEmail, comparePassword } = require('../models/userModel');
const jwt = require('jsonwebtoken');
require('dotenv').config();

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

module.exports = { signup, login };
