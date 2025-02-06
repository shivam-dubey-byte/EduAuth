const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const connectDB = require('../connectDB');
const { console } = require('inspector');

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

const findUserById = async (id) => {
  const db = await connectDB("user");
  const collection = db.collection('users');
  const user = await collection.findOne({ _id: id });
  return user;
};

const updatePassword = async (id, pass) => {
  const db = await connectDB("user");
  const collection = db.collection('users');
  const password = await bcrypt.hash(pass, 10);
  console.log(password);
  const result = await collection.updateOne({ _id: id }, { $set: { password}});
  return result;
};

module.exports = { createUser, findUserByEmail, comparePassword, findUserById,updatePassword };
