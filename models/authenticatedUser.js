const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// set up a mongoose model
module.exports = mongoose.model('AuthenticatedUser', new Schema({ 
    passwordHash: String,
    email: {type: String, lowercase: true, unique: true},
    banned: Boolean,
    administrator: Boolean
}));