const mongoose = require('mongoose')
const userShema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        lowercase: true,
        unique: true,
    },
    password: {
        type: String,
        required: true
    }
})
const User = mongoose.model("healthCareUser", userShema)

module.exports = User