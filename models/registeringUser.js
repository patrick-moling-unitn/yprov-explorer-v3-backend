const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// set up a mongoose model
module.exports = mongoose.model('RegisteringUser', new Schema({ 
    passwordHash: String,
    email: {type: String, lowercase: true, unique: true},
    verificationCode: {
        code: String,
        expireDate: {
            type: Date,
            index: { expires: 0 }
        },
        attempts: {
            type: Number,
            default: 0
        },
        secret: String
    }
}));