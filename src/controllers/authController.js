const {
  createUser,
  findUserByEmail,
  comparePassword,
  findUserById,
  updatePassword
} = require('../models/userModel');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const { sendResetEmail } = require('../mail/resetMail');
const { ObjectId } = require('mongodb');

console.log("JWT_SECRET:", process.env.JWT_SECRET); // Debugging to ensure it's loaded

// Profile image mapping based on the first letter of email
const profileImageLinks = {
    a: "https://i.imgur.com/829pqfV.jpg",
    b: "https://i.imgur.com/rnpqVhK.jpg",
    c: "https://i.imgur.com/KDmboxg.jpg",
    d: "https://i.imgur.com/6oTdEsH.jpg",
    e: "https://i.imgur.com/mC8nIrj.jpg",
    f: "https://i.imgur.com/wuL54zd.jpg",
    g: "https://i.imgur.com/6Bc7L3h.jpg",
    h: "https://i.imgur.com/dzGGWtD.jpg",
    i: "https://i.imgur.com/bfgkLdm.jpg",
    j: "https://i.imgur.com/UNwFW7J.jpg",
    k: "https://i.imgur.com/p250FFA.jpg",
    l: "https://i.imgur.com/undefined.jpg",
    m: "https://i.imgur.com/7z2t4m5.jpg",
    n: "https://i.imgur.com/E1FqdIT.jpg",
    o: "https://i.imgur.com/lTdf4pZ.jpg",
    p: "https://i.imgur.com/YWIpqnV.jpg",
    q: "https://i.imgur.com/OwyQilG.jpg",
    r: "https://i.imgur.com/d7C0di.jpg",
    s: "https://i.imgur.com/undefin.jpged",
    t: "https://i.imgur.com/MKzutOv.jpg",
    u: "https://i.imgur.com/jZ0zoqK.jpg",
    v: "https://i.imgur.com/H6og9ez.jpg",
    w: "https://i.imgur.com/lpC7Ghr.jpg",
    x: "https://i.imgur.com/lWZMLyq.jpg",
    y: "https://i.imgur.com/undefined.jpg",
    z: "https://i.imgur.com/undefined.jpg"
};

// **User Signup**
const signup = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user already exists
    let user = await findUserByEmail(email);
    if (user) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Hash password
    //const hashedPassword = await bcrypt.hash(password, 10);

    // Get first letter of email & assign profile image
    const firstLetter = email.charAt(0).toLowerCase();
    const profileImage = profileImageLinks[firstLetter] || "https://i.imgur.com/default.jpg";

    // Create new user
    await createUser(email, password, profileImage);

    // Fetch newly created user
    const newUser = await findUserByEmail(email);

    // Generate token
    const token = jwt.sign({ id: newUser._id,  email: newUser.email }, process.env.JWT_SECRET, { expiresIn: "15d" });

    res.status(201).json({
      message: "User registered successfully",
      token,
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        profile: newUser.profile
      }
    });
  } catch (error) {
    console.error("Signup Error:", error);
    res.status(500).json({ message: "Server error", error });
  }
};

// **User Login**
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user in DB
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Compare passwords
    const isMatch = await comparePassword(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Generate JWT Token
    const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: "15d",
    });

    res.status(200).json({ message: "Login successful", token, user: { profile: user.profile } });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ error: "Server error" });
  }
};

// **Forgot Password Controller**
const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const resetToken = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "15d" });

    const resetUrl = `https://knowledgesun.quantumsoftdev.in/reset-password/${resetToken}`;
    await sendResetEmail(user.email, resetUrl);

    res.status(200).json({ message: "Password reset email sent" });
  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.status(500).json({ message: "Server error", error });
  }
};

// **Reset Password Controller**
const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    console.log("Received Token:", token);

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Decoded Token:", decoded);

    const { email } = decoded;

    // Find the user
    const user = await findUserByEmail(email);
    console.log("User Found:", user);

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await updatePassword(user._id, hashedPassword);

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    console.error("Reset Password Error:", error);
    res.status(500).json({ message: "Server error", error });
  }
};

module.exports = { signup, login, forgotPassword, resetPassword };
