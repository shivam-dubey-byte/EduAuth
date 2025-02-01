const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const connectDB = require('../connectDB');

// Function to create a new user in the database
const createUser = async (email, password) => {
  const db = await connectDB("user");
  const collection = db.collection('users');  // 'users' is your MongoDB collection

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = { email, password: hashedPassword };

  // Insert the new user into the database
  const result = await collection.insertOne(user);
  return result.insertedId;
};

// Function to find a user by email
const findUserByEmail = async (email) => {
  const db = await connectDB("user");
  const collection = db.collection('users');

  const user = await collection.findOne({ email });
  return user;
};

// Function to compare password
const comparePassword = async (password, hashedPassword) => {
  return bcrypt.compare(password, hashedPassword);
};

module.exports = { createUser, findUserByEmail, comparePassword };
