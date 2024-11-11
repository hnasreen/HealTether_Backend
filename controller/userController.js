import User from "../models/user.js";
import bcrypt from 'bcryptjs';
import JWT from 'jsonwebtoken';

// Helper function for validating email format
const isValidEmail = (email) => {
  const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
  return emailRegex.test(email);
};

// Helper function for validating username (only alphabets and spaces allowed)
const isValidUsername = (name) => {
  const nameRegex = /^[a-zA-Z\s]+$/;
  return nameRegex.test(name);
};

// Helper function for password validation (min 6 characters)
const isValidPassword = (password) => {
  return password && password.length >= 6;
};

export const register = async (req, res) => {
  const { name, email, password } = req.body;

  // Validate input data
  if (!name || !email || !password) {
    return res.status(400).json({ success:false, message: "All fields are required" });
  }

  if (!isValidUsername(name)) {
    return res.status(400).json({ success:false,message: "Name must only contain alphabets and spaces" });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ success:false,message: "Invalid email format" });
  }

  if (!isValidPassword(password)) {
    return res.status(400).json({ success:false,message: "Password must be at least 6 characters" });
  }

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({success:false, message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    await user.save();
    res.status(201).json({
      message: "Registered Successfully",
      success: true,
    });
  } catch (error) {
    res.status(500).json({ message: "Error during Register", error });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  // Validate input data
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const passwordCheck = await bcrypt.compare(password, user.password);
    if (!passwordCheck) {
      return res.status(400).json({ message: "Invalid Password" });
    }

    const token = JWT.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    return res.status(200).json({ token, message: "Successfully Logged In", success: true });
  } catch (error) {
    res.status(500).json({ message: "Error during Login", error });
  }
};

// Forgot Password
export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  // Validate email format
  if (!isValidEmail(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Email not found" });
    }

    const token = JWT.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ success: true, token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};

// Reset Password
export const resetPassword = async (req, res) => {
  const { password } = req.body;

  if (!isValidPassword(password)) {
    return res.status(400).json({ success:false,message: "Password must be at least 6 characters" });
  }

  try {
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(400).json({success:false, message: "User not found" });
    }

    // Check if the new password is the same as the current one
    const isSamePassword = await bcrypt.compare(password, user.password);
    if (isSamePassword) {
      return res.status(400).json({ success:false,message: "New password must be different from the old one" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate(req.user.userId, { password: passwordHash });

    res.json({ success: true, message: "Password updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating password", error });
    console.log(error);
  }
};

export const getUser = async (req, res) => {
  try {
    // `req.user` will be populated by the authentication middleware
    const user = await User.findById(req.user.id);  // Use `_id` to find the user
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ username: user.name });  // Send back the username
  } catch (error) {
    res.status(500).json({ message: 'Error Fetching the User Details' });
    console.log(error);
  }
};
