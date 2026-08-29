const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// set up a mongoose model
module.exports = mongoose.model('AuthenticatedUser', new Schema({ 
    passwordHash: String,
    email: {type: String, lowercase: true, unique: true},
    banned: {type: Boolean, default: false},
    administrator: {type: Boolean, default: false},
    superAdministrator: {type: Boolean, default: false},
    lastLogin: Date
}));