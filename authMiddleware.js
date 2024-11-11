import JWT from "jsonwebtoken";

const authMiddleware = async (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json("User Authentication Failed");
  try {
    const decoded = await JWT.verify(token, process.env.JWT_SECRET);
    req.user = decoded; 
    next();
  } catch (error) {
    res.status(401).json("User Authentication Failed");
  }
};

export default authMiddleware;