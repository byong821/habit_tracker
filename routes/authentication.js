// routes/authentication.js
// Handles user authentication: login and registration
import { Router } from "express";
import { getDB } from "../db/connect.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const router = Router();

// POST /api/auth/login - User login endpoint
router.post("/login", async (req, res, next) => {
  try {
    const { password, email } = req.body;
    
    // Find user by email
    const user = await getDB().collection("users").findOne({ email });
    if (!user)
      return res.status(401).json({ error: "Invalid email or password" });

    // Verify password
    const result = bcrypt.compareSync(password, user.password);
    if (!result)
      return res.status(401).json({ error: "Invalid email or password" });

    // Generate JWT token
    const token = jwt.sign({ email, id: user._id }, process.env.JWT_SECRET);

    // Update last login timestamp
    getDB()
      .collection("users")
      .updateOne({ _id: user._id }, { $set: { lastLoginAt: new Date() } });

    res
      .status(200)
      .header("Authorization", `Bearer ${token}`)
      .json({
        message: "Login successful",
        token,
        user: {
          name: user.name,
          email,
          lastLoginAt: new Date(),
        },
      });
  } catch (e) {
    next(e);
  }
});

// POST /api/auth/register - User registration endpoint
router.post("/register", async (req, res, next) => {
  try {
    const { password, name, email } = req.body;

    // Check if user already exists
    const user = await getDB().collection("users").findOne({ email });
    if (user)
      return res.status(400).json({
        error: "Email already exists",
      });

    // Create new user with hashed password
    const newUser = await getDB()
      .collection("users")
      .insertOne({
        password: bcrypt.hashSync(password, 10),
        name,
        email,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLoginAt: new Date(),
      });

    res
      .status(201)
      .header(
        "Authorization",
        `Bearer ${jwt.sign({ email, id: newUser.insertedId }, process.env.JWT_SECRET)}`
      )
      .json({
        message: "Registration successful",
        user: {
          name,
          email,
        },
      });
  } catch (e) {
    next(e);
  }
});

export default router;
