import mongoose from "mongoose";

type User = {
    fullName: string;
    email: string;
    profileImage: string;
    password: string;
};

const userSchema = new mongoose.Schema<User>({
    fullName: {
        type: String,
        minLength: [5, 'Full name must be at least 5 characters long'],
        required: [true, 'Full name is required'],
        trim: true
    },
    email: {
        type: String,
        match: [/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/, 'Please enter a valid email address'],
        required: [true, 'Email is required'],
        unique: true,
        trim: true,
        lowercase: true,
        index: true
    },
    profileImage: {
        type: String,
        required: [true, "Profile image is required"],
    },
    password: {
        type: String,
        required: true,
    },
});

export const userModel = mongoose.model('User', userSchema);