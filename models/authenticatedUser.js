const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// set up a mongoose model
module.exports = mongoose.model('AuthenticatedUser', new Schema({ 
    passwordHash: String,
    email: {type: String, lowercase: true, unique: true},
    banned: {type: Boolean, default: false},
    role: {
        type: String,
        enum: ['User', 'Admin', 'SuperAdmin'],
        default: 'User'
    },
    lastLogin: { type: Date, default: null },
    settings: {
        saveLogin: {type: Boolean, default: true}
    }
}));