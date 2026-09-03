const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// set up a mongoose model
module.exports = mongoose.model('RefreshToken', new Schema({ 
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'AuthenticatedUser',
        index: true
    },
    tokenHash: String,
    rotated: {
        type: Boolean,
        default: false
    },
    expireDate: {
        type: Date,
        index: { expires: "30m" }
    }
}));