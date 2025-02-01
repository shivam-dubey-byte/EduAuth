const express = require('express');
//const connectDB = require('./connectDB');
//const cors = require('cors');
//require('dotenv').config();

//const authRoutes = require('./routes/authRoutes');

const app = express();
app.use(express.json());
//app.use(cors());

//app.use('/auth', authRoutes);

app.get('/', (req, res) => {
  res.send('Hello, World!');
});



//connectDB();
//app.connectDB();
//connectToDatabase();
module.exports = app;
//srd191104
//ECWKUWWYT2QHPWR1
//sQWpdHYV38rvG8uG
