const { createUser, findUserByEmail, comparePassword,findUserById, updatePassword } = require('../models/userModel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const { sendResetEmail } = require('../mail/resetMail');


// Profile image mapping based on first letter of email
const profileImageLinks = {
    a: "https://imgur.com/829pqfV",
    b: "https://imgur.com/rnpqVhK",
    c: "https://imgur.com/KDmboxg",
    d: "https://imgur.com/6oTdEsH",
    e: "https://imgur.com/mC8nIrj",
    f:"https://imgur.com/wuL54zd",
    g:"https://imgur.com/6Bc7L3h",
    h:"https://imgur.com/dzGGWtD",
    i:"https://imgur.com/bfgkLdm",
    j:"https://imgur.com/UNwFW7J",
    k:"https://imgur.com/p250FFA",
    l:"https://imgur.com/undefined",
    m:"https://imgur.com/7z2t4m5",
    n:"https://imgur.com/E1FqdIT",
    o:"https://imgur.com/lTdf4pZ",
    p:"https://imgur.com/YWIpqnV",
    q:"https://imgur.com/OwyQilG",
    r:"https://imgur.com/d7C0dih",
    s:"https://imgur.com/undefined",
    t:"https://imgur.com/MKzutOv",
    u:"https://imgur.com/jZ0zoqK",
    v:"https://imgur.com/H6og9ez",
    w:"https://imgur.com/lpC7Ghr",
    x:"https://imgur.com/lWZMLyq",
    y:"https://imgur.com/undefined",
    z: "https://imgur.com/undefined"
};




// User Signup
const signup = async (req, res) => {
  try {
      const { name, email, password } = req.body;

      // Check if user already exists
      let user = await User.findOne({ email });
      if (user) {
          return res.status(400).json({ message: "User already exists" });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Get first letter of email & convert to lowercase
      const firstLetter = email.charAt(0).toLowerCase();

      // Assign profile image based on first letter, use default if not found
      const profileImage = profileImageLinks[firstLetter];

      // Create new user
      user = new User({
          name,
          email,
          password: hashedPassword,
          profile: profileImage // Store profile image link
      });

      await user.save();

      // Generate token
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

      res.status(201).json({
          message: "User registered successfully",
          token,
          user: {
              id: user._id,
              name: user.name,
              email: user.email,
              profile: user.profile
          }
      });
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error" });
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
      expiresIn: '15d',
    });

    res.status(200).json({ message: 'Login successful', token,user:{profile: users.profile} });
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
      const resetToken = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET, {expiresIn: '15d',});

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
