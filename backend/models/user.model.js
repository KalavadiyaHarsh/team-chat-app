import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        minLength: [6, 'Email must be at least 6 characters long'],
        maxLength: [50, 'Email must not be longer than 50 characters']
    },
    password: {
        type: String,
        select: false,
    },
    logoutAt: {
        type: Date,
        default: null, // Store last logout time
    }
});

userSchema.statics.hashPassword = async function (password) {
    return await bcrypt.hash(password, 10);
};

userSchema.methods.isValidPassword = async function (password) {
    return await bcrypt.compare(password, this.password);
};

// Generate JWT with issued time (iat)
userSchema.methods.generateJWT = function () {
    return jwt.sign(
        { email: this.email, id: this._id, iat: Math.floor(Date.now() / 1000) },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
    );
};

// Check if the token is still valid (not logged out)
userSchema.methods.isTokenValid = function (tokenIssuedAt) {
    return !this.logoutAt || new Date(tokenIssuedAt * 1000) > new Date(this.logoutAt);
};

const User = mongoose.model('User', userSchema);
export default User;
