const mongoose = require('mongoose');
const user = new mongoose.Schema({
    name:String,
    id:String
});
module.exports = mongoose.model('users',user)