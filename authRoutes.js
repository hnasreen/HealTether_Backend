import express from "express";
import {
  forgotPassword,
  getUser,
  login,
  register,
  resetPassword,
} from "./controller/userController.js";
import authMiddleware from "./authMiddleware.js";
const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", authMiddleware, resetPassword);
router.get("/getuser", authMiddleware, getUser);

export default router;
