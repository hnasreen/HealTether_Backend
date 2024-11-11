import express from "express";
import dotenv from "dotenv";
import authRoutes from "./authRoutes.js";
import connectdb from "./db.js";
import cors from "cors";
import morgan from "morgan";

const app = express();
dotenv.config();
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  })
);

app.use(express.json());
app.use(morgan("dev"));

app.use("/api", authRoutes);
connectdb();
app.get("/", (req, res) => {
  res.send("<h1>BackEnd</h1>");
});
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log("Application is running on the port:", PORT);
});
