const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const { verifyToken } = require("../middleware/auth");
const { sendEmail2FACode } = require("../utils/mailer");
const crypto = require("crypto");
const JWT_SECRET = process.env.JWT_SECRET;

// ============================
// HELPER: Generate Backup Codes
// ============================
const generateBackupCodes = () => {
  return Array.from({ length: 10 }, () =>
    Math.random().toString(36).substring(2, 10).toUpperCase()
  );
};

// ============================
// ROUTE 1: Register
// ============================
router.post("/register", async (req, res) => {
  try {
    const { email, password, firstName, lastName, department } = req.body;

    // Validation
    if (!email || !password || !firstName || !lastName || !department) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    // Create new user
    const user = new User({
      email,
      password,
      firstName,
      lastName,
      department,
    });

    await user.save();

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        department: user.department,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================
// ROUTE 2: Login (Password Only)
// ============================
router.post("/login", async (req, res) => {
  try {
    const { email, password, department } = req.body;

    if (!email || !password || !department) {
      return res
        .status(400)
        .json({ error: "Email, password, and department are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    if (user.department !== department) {
      return res.status(400).json({ error: "Department mismatch" });
    }

    // EMAIL-BASED 2FA
    if (user.twoFactorEnabled && user.twoFactorMethod === "email") {
      // Generate 6-digit code
      const code = crypto.randomInt(100000, 999999).toString();

      // Save code and expiration
      user.twoFactorEmailCode = await bcrypt.hash(code, 10);
      user.twoFactorEmailExpires = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
      await user.save();

      // Send email using your mailer
      try {
        await sendEmail2FACode(user.email, code);
      } catch (err) {
        return res
          .status(500)
          .json({ error: "Failed to send 2FA code, please try again" });
      }
      // New code
      const tempToken = jwt.sign(
        { id: user._id, tempAccess: true }, // include user ID and tempAccess flag
        JWT_SECRET,
        { expiresIn: "5m" } // token valid for 5 minutes
      );
      return res.json({
        requiresTwoFactor: true,
        tempToken, // ✅ use the JWT you just created
      });
    }

    // If no 2FA enabled, issue full token
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        department: user.department,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// ROUTE 3: Google Login
router.post("/google-login", async (req, res) => {
  try {
    const { token, department } = req.body;
    if (!token || !department)
      return res.status(400).json({ error: "Token and department required" });

    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { sub, email, name, picture } = payload;

    let user = await User.findOne({ email });
    if (!user) {
      const gFirstName = name ? name.split(" ")[0] : "";
      const gLastName = name ? name.split(" ").slice(1).join(" ") : "";
      user = new User({ firstName: gFirstName, lastName: gLastName, email, googleId: sub, picture, department });
      await user.save();
    } else if (!user.department) {
      user.department = department;
      await user.save();
    }

    if (user.twoFactorEnabled && user.twoFactorMethod === "email") {
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      user.twoFactorEmailCode = await bcrypt.hash(code, 10);
      user.twoFactorEmailExpires = Date.now() + 5 * 60 * 1000;
      await user.save();

      await sendEmail2FACode(user.email, code);

      const tempToken = jwt.sign(
        { id: user._id, email: user.email, tempAccess: true },
        JWT_SECRET,
        { expiresIn: "5m" }
      );
      return res.json({
        requiresTwoFactor: true,
        twoFactorMethod: "email",
        tempToken,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          department: user.department,
        },
      });
    }

    const jwtToken = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });
    res.json({ success: true, token: jwtToken, user });
  } catch (error) {
    console.error("Google login error:", error);
    res.status(400).json({ error: "Invalid Google token" });
  }
});

// ROUTE 4: Check if Google User Exists
router.post("/check-google-user", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res
        .status(400)
        .json({ error: "Email is required", exists: false });

    const user = await User.findOne({ email });
    if (user) {
      res.json({
        exists: true,
        user: {
          id: user._id,
          email: user.email,
          name: user.name,
          department: user.department,
          twoFactorEnabled: user.twoFactorEnabled,
        },
      });
    } else {
      res.json({ exists: false });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to check user", exists: false });
  }
});

// ============================
// ROUTE 5: Verify 2FA Code During Login
// ============================
router.post("/verify-2fa-code", async (req, res) => {
  try {
    const { tempToken, code } = req.body;

    if (!tempToken)
      return res.status(400).json({ error: "Temp token is required" });

    // Always treat code as string
    const enteredCode = String(code || "").trim();
    if (enteredCode.length !== 6) {
      return res
        .status(400)
        .json({ error: "A valid 6-digit code is required" });
    }

    // Verify temp token
    let decoded;
    try {
      decoded = jwt.verify(tempToken, JWT_SECRET);
    } catch {
      return res.status(401).json({ error: "Token expired or invalid" });
    }

    if (!decoded.tempAccess) {
      return res.status(401).json({ error: "Invalid token" });
    }

    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Check email 2FA code
    if (!user.twoFactorEmailCode || !user.twoFactorEmailExpires) {
      return res.status(400).json({ error: "2FA code not set" });
    }

    if (Date.now() > user.twoFactorEmailExpires) {
      return res.status(400).json({ error: "2FA code expired" });
    }

    // Compare hashed code
    const isValid = await bcrypt.compare(enteredCode, user.twoFactorEmailCode);
    if (!isValid) return res.status(400).json({ error: "Invalid 2FA code" });

    // Clear code
    user.twoFactorEmailCode = null;
    user.twoFactorEmailExpires = null;
    await user.save();

    // Issue full JWT
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        department: user.department,
      },
    });
  } catch (error) {
    console.error("Verify 2FA code error:", error);
    res.status(500).json({ error: "Verification failed" });
  }
});

// ============================
// ROUTE 6: Disable 2FA
// ============================
router.post("/disable-2fa", verifyToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(
      req.user.id,
      {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        backupCodes: [],
      },
      { new: true }
    );

    res.json({ success: true, message: "2FA disabled" });
  } catch (error) {
    res.status(500).json({ error: "Failed to disable 2FA" });
  }
});

// ============================
// ROUTE 7: Get User 2FA Status
// ============================
router.get("/2fa-status", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.json({
      twoFactorEnabled: user.twoFactorEnabled,
      twoFactorMethod: user.twoFactorMethod,
      backupCodesRemaining: user.backupCodes.length,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to get 2FA status" });
  }
});
// ============================
// ROUTE 8: Get User App Settings
// ============================
router.get("/settings", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("settings");

    res.json(user.settings);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch settings" });
  }
});
// ============================
// ROUTE 9: Update User App Settings
// ============================
router.put("/settings", verifyToken, async (req, res) => {
  try {
    const updates = req.body;

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: { settings: updates } },
      { new: true }
    );

    res.json({
      success: true,
      settings: user.settings,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to update settings" });
  }
});
// ============================
// ROUTE 10: Get User Profile
// ============================
router.get("/profile", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "-password -twoFactorSecret -backupCodes"
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user); // <-- IMPORTANT: returns _id
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch user profile" });
  }
});

module.exports = router;
