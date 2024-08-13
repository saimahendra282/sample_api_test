// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  dob: { type: Date, required: true },
  super_coin_bal: { type: Number, default: 99 },
});

const User = mongoose.model('User', userSchema);

module.exports = User;
