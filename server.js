const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
require("dotenv").config();
const { sendEmail2FACode } = require("./utils/mailer");
const app = express();
const User = require("./models/User");

// ✅ NEW: OTP routes
const otpRoutes = require("./routes/otp");

app.use(cors());
app.use(bodyParser.json());

// Google OAuth client
const client = new OAuth2Client(
  "609775986703-3mdih863emnqm8qc7utkfb3jkdoghgg4.apps.googleusercontent.com",
);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "secret123";

// ============================
// MULTER CONFIGURATION FOR FILE UPLOADS
// ============================
const uploadsDir = path.join(__dirname, "uploads", "profiles");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/profiles");
  },
  filename: (req, file, cb) => {
    const uniqueName =
      req.user.id + "-" + Date.now() + path.extname(file.originalname);
    cb(null, uniqueName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 1 * 1024 * 1024 }, // 1MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/jpg", "image/png"];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Only JPG, JPEG, and PNG images are allowed"), false);
    }
    cb(null, true);
  },
});

// Root route
app.get("/", (req, res) => {
  res.send("Server is running!");
});

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "Server is running" });
});

// Connect MongoDB
const rawMongoUri =
  process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/myapp";
const mongoUri = rawMongoUri.replace(
  "mongodb://localhost:",
  "mongodb://127.0.0.1:",
);

mongoose
  .connect(mongoUri, { serverSelectionTimeoutMS: 5000 })
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => console.error("❌ MongoDB connection failed:", err));

// ============================
// Middleware: Verify JWT Token
// ============================
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Unauthorized - No token provided" });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

// ============================
// Helper: Generate Backup Codes
// ============================
const generateBackupCodes = () => {
  return Array.from({ length: 10 }, () =>
    Math.random().toString(36).substring(2, 10).toUpperCase(),
  );
};

// ============================
// ✅ NEW: Register OTP routes
// Registers: POST /auth/send-otp, /auth/verify-otp, /auth/resend-otp
// ============================
app.use("/auth", otpRoutes);

// ============================
// ROUTE 1: Registration
// ✅ UPDATED: now requires verifiedToken from OTP step
// ============================
app.post("/register", async (req, res) => {
  try {
    const { firstName, lastName, email, password, department, verifiedToken } = req.body;

    // Basic field validation
    if (!firstName || !lastName || !email || !password || !department) {
      return res.status(400).json({
        success: false,
        error: "All fields are required",
      });
    }

    // Require email verification token
    if (!verifiedToken) {
      return res.status(400).json({
        success: false,
        error: "Email verification is required before registration",
      });
    }

    // Validate the verifiedToken
    let decoded;
    try {
      decoded = jwt.verify(verifiedToken, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({
        success: false,
        error:
          "Email verification expired or invalid. Please verify your email again.",
      });
    }

    if (!decoded.emailVerified) {
      return res.status(401).json({
        success: false,
        error: "Email not verified. Please complete the OTP verification step.",
      });
    }

    // Ensure the token matches the email being registered
    if (decoded.email !== email.toLowerCase()) {
      return res.status(400).json({
        success: false,
        error: "Verification token does not match the provided email address.",
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: "An account with this email already exists.",
      });
    }

    // Create and save user (pre-save hook handles password hashing)
    const user = new User({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password,
      department,
    });
    await user.save();

    // Issue full auth JWT
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    console.log(`✅ New user registered: ${user.email}`);

    res.json({
      success: true,
      message: "Registration successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        department: user.department,
      },
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ success: false, error: "Server error. Try again." });
  }
});

// ============================
// ROUTE 2: Login (Password Only)
// ============================
app.post("/login", async (req, res) => {
  try {
    const { email, password, department } = req.body;
    if (!email || !password || !department)
      return res
        .status(400)
        .json({ error: "Email, password, department required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Incorrect password" });

    if (user.department !== department)
      return res.status(401).json({
        error: `Department mismatch. Registered with ${user.department}`,
      });

    if (user.twoFactorEnabled) {
      const code = Math.floor(100000 + Math.random() * 900000).toString();

      user.twoFactorEmailCode = await bcrypt.hash(code, 10);
      user.twoFactorEmailExpires = Date.now() + 5 * 60 * 1000;
      await user.save();

      await sendEmail2FACode(user.email, code);

      const tempToken = jwt.sign(
        { id: user._id, email: user.email, tempAccess: true },
        JWT_SECRET,
        { expiresIn: "5m" },
      );

      return res.json({
        requiresTwoFactor: true,
        twoFactorMethod: "email",
        tempToken,
      });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });
    res.json({ success: true, token, user });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ============================
// ROUTE 2.5: Check if Google User Exists
// ============================
app.post("/check-google-user", async (req, res) => {
  try {
    const { email } = req.body;

    console.log("Checking if user exists:", email);

    if (!email) {
      return res.status(400).json({
        error: "Email is required",
        exists: false,
      });
    }

    const user = await User.findOne({ email });

    if (user) {
      console.log("User found:", user.email);
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
      console.log("User not found:", email);
      res.json({ exists: false });
    }
  } catch (error) {
    console.error("Check Google user error:", error);
    res.status(500).json({
      error: "Failed to check user",
      exists: false,
    });
  }
});

// ============================
// ROUTE 3: Google Login
// ============================
app.post("/google-login", async (req, res) => {
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

    if (user.twoFactorEnabled) {
      const code = Math.floor(100000 + Math.random() * 900000).toString();

      user.twoFactorEmailCode = await bcrypt.hash(code, 10);
      user.twoFactorEmailExpires = Date.now() + 5 * 60 * 1000;
      await user.save();

      await sendEmail2FACode(user.email, code);

      const tempToken = jwt.sign(
        { id: user._id, email: user.email, tempAccess: true },
        JWT_SECRET,
        { expiresIn: "5m" },
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

// ============================
// ROUTE: Get User Profile
// ============================
app.get("/api/user/profile", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    console.log(
      "📋 Fetching profile for user:",
      user.email,
      "Department:",
      user.department,
    );

    res.json({
      id: user._id,
      firstName: user.firstName || "",
      lastName: user.lastName || "",
      fullName: user.name || "",
      email: user.email || "",
      department: user.department || "",
      role: user.role || "",
      phoneNumber: user.phoneNumber || "",
      picture: user.picture || "",
      notifications: user.notifications,
      twoFactorEnabled: user.twoFactorEnabled,
    });
  } catch (error) {
    console.error("Get profile error:", error);
    res.status(500).json({ error: "Failed to fetch profile" });
  }
});

// ============================
// ROUTE: Upload profile photo
// ============================
app.post(
  "/api/user/upload-photo",
  verifyToken,
  upload.single("photo"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
      }

      const photoUrl = `http://localhost:5001/uploads/profiles/${
        req.file.filename
      }?t=${Date.now()}`;

      const user = await User.findById(req.user.id);
      if (user && user.picture) {
        const oldPhotoPath = path.join(
          __dirname,
          "uploads",
          "profiles",
          path.basename(user.picture.split("?")[0]),
        );
        if (fs.existsSync(oldPhotoPath)) {
          fs.unlinkSync(oldPhotoPath);
        }
      }

      const updatedUser = await User.findByIdAndUpdate(
        req.user.id,
        { picture: photoUrl },
        { new: true },
      );

      console.log(
        "✅ Photo uploaded successfully for user:",
        updatedUser.email,
      );

      res.json({
        success: true,
        message: "Photo uploaded successfully",
        photoUrl: photoUrl,
        user: {
          id: updatedUser._id,
          picture: updatedUser.picture,
        },
      });
    } catch (error) {
      console.error("Upload photo error:", error);
      if (error.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({
          error: "File is too large. Maximum allowed size is 1MB.",
        });
      }
      res.status(500).json({ error: "Failed to upload photo" });
    }
  },
);

// ============================
// ROUTE: Delete profile photo
// ============================
app.delete("/api/user/delete-photo", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.picture) {
      const photoPath = path.join(
        __dirname,
        "uploads",
        "profiles",
        path.basename(user.picture.split("?")[0]),
      );
      if (fs.existsSync(photoPath)) {
        fs.unlinkSync(photoPath);
      }
    }

    user.picture = null;
    await user.save();

    res.json({ success: true, message: "Profile photo deleted" });
  } catch (error) {
    console.error("Delete photo error:", error);
    res.status(500).json({ error: "Failed to delete profile photo" });
  }
});

// ============================
// ROUTE: Verify 2FA Setup & Enable
// ============================
app.post("/auth/verify-2fa-setup", verifyToken, async (req, res) => {
  try {
    const { code, backupCodes, secret } = req.body;

    if (!code || !secret) {
      return res.status(400).json({ error: "Code and secret are required" });
    }

    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token: code,
      window: 2,
    });

    if (!verified) {
      return res.status(400).json({ error: "Invalid verification code" });
    }

    const hashedBackupCodes = await Promise.all(
      backupCodes.map((code) => bcrypt.hash(code, 10)),
    );

    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        twoFactorEnabled: true,
        twoFactorSecret: secret,
        backupCodes: hashedBackupCodes,
        twoFactorMethod: "totp",
      },
      { new: true },
    );

    res.json({ success: true, message: "2FA enabled successfully" });
  } catch (error) {
    console.error("Verify 2FA setup error:", error);
    res.status(500).json({ error: "Verification failed" });
  }
});

// ============================
// ROUTE: Enable email 2FA
// ============================
app.post("/auth/enable-2fa", verifyToken, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        twoFactorEnabled: true,
        twoFactorMethod: "email",
      },
      { new: true },
    );

    res.json({
      success: true,
      message: "2FA enabled successfully",
      twoFactorEnabled: user.twoFactorEnabled,
      twoFactorMethod: user.twoFactorMethod,
    });
  } catch (error) {
    console.error("Enable 2FA error:", error);
    res.status(500).json({ error: "Failed to enable 2FA" });
  }
});

// ============================
// ROUTE: Verify 2FA Code During Login
// ============================
app.post("/auth/verify-2fa-code", async (req, res) => {
  try {
    const { tempToken, code } = req.body;

    if (!tempToken || !code) {
      return res.status(400).json({ error: "Token and code are required" });
    }

    const enteredCode = String(code).trim();
    if (enteredCode.length !== 6) {
      return res.status(400).json({ error: "Code must be 6 digits" });
    }

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

    if (!user.twoFactorEmailCode || !user.twoFactorEmailExpires) {
      return res.status(400).json({ error: "2FA code not set" });
    }

    if (Date.now() > user.twoFactorEmailExpires) {
      return res.status(400).json({ error: "2FA code expired" });
    }

    const isValid = await bcrypt.compare(enteredCode, user.twoFactorEmailCode);
    if (!isValid) return res.status(400).json({ error: "Invalid 2FA code" });

    user.twoFactorEmailCode = null;
    user.twoFactorEmailExpires = null;
    await user.save();

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        department: user.department,
      },
      method: "email",
    });
  } catch (error) {
    console.error("Verify 2FA code error:", error);
    res.status(500).json({ error: "Verification failed" });
  }
});

// ============================
// ROUTE: Disable 2FA
// ============================
app.post("/auth/disable-2fa", verifyToken, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        backupCodes: [],
      },
      { new: true },
    );

    res.json({ success: true, message: "2FA disabled" });
  } catch (error) {
    console.error("Disable 2FA error:", error);
    res.status(500).json({ error: "Failed to disable 2FA" });
  }
});

// ============================
// ROUTE: Get User 2FA Status
// ============================
app.get("/auth/2fa-status", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.json({
      twoFactorEnabled: user.twoFactorEnabled,
      twoFactorMethod: user.twoFactorMethod,
      backupCodesRemaining: user.backupCodes.length,
    });
  } catch (error) {
    console.error("Get 2FA status error:", error);
    res.status(500).json({ error: "Failed to get 2FA status" });
  }
});

// ============================
// ROUTE: Update user profile
// ============================
app.put("/api/user/profile", verifyToken, async (req, res) => {
  try {
    const { firstName, lastName, email, department, role, phoneNumber } = req.body;

    if (!firstName || !lastName || !department) {
      return res
        .status(400)
        .json({ error: "First name, last name, and department are required" });
    }

    if (email && email !== req.user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: "Email already in use" });
      }
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        firstName,
        lastName,
        email: email || req.user.email,
        department,
        role: role || "",
        phoneNumber: phoneNumber || "",
      },
      { new: true },
    );

    console.log("✅ Profile updated for user:", user.email);

    res.json({
      success: true,
      message: "Profile updated successfully",
      user: {
        id: user._id,
        fullName: user.name,
        email: user.email,
        department: user.department,
        role: user.role,
        phoneNumber: user.phoneNumber,
        picture: user.picture,
      },
    });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

// ============================
// ROUTE: Change password
// ============================
app.post("/api/user/change-password", verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "Both passwords are required" });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isValid = await bcrypt.compare(currentPassword, user.password);
    if (!isValid) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(req.user.id, { password: hashedPassword });

    res.json({ success: true, message: "Password changed successfully" });
  } catch (error) {
    console.error("Change password error:", error);
    res.status(500).json({ error: "Failed to change password" });
  }
});

// ============================
// ROUTE: Update notification preferences
// ============================
app.put("/api/user/notifications", verifyToken, async (req, res) => {
  try {
    const {
      emailNotifications,
      smsAlerts,
      pushNotifications,
      incidentAlerts,
      complianceReminders,
      weeklyReports,
    } = req.body;

    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        notifications: {
          emailNotifications,
          smsAlerts,
          pushNotifications,
          incidentAlerts,
          complianceReminders,
          weeklyReports,
        },
      },
      { new: true },
    );

    res.json({
      success: true,
      message: "Notification settings updated",
      notifications: user.notifications,
    });
  } catch (error) {
    console.error("Update notifications error:", error);
    res.status(500).json({ error: "Failed to update notification settings" });
  }
});

// ============================
// ROUTE: Generate 2FA
// ============================
app.post("/auth/generate-2fa", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.twoFactorMethod === "email") {
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      user.twoFactorEmailCode = await bcrypt.hash(code, 10);
      user.twoFactorEmailExpires = Date.now() + 5 * 60 * 1000;
      await user.save();
      await sendEmail2FACode(user.email, code);

      return res.json({
        success: true,
        twoFactorMethod: "email",
        message: "2FA code sent to email",
      });
    }

    const secret = speakeasy.generateSecret({ length: 20 });
    const backupCodes = generateBackupCodes();
    const qrCode = await QRCode.toDataURL(secret.otpauth_url);

    res.json({
      twoFactorMethod: "totp",
      secret: secret.base32,
      qrCode,
      backupCodes,
    });
  } catch (error) {
    console.error("Generate 2FA error:", error);
    res.status(500).json({ error: "Failed to generate 2FA" });
  }
});

// ============================
// ROUTE: Verify email 2FA
// ============================
app.post("/auth/verify-email-2fa", async (req, res) => {
  try {
    const { tempToken, code } = req.body;

    if (!tempToken || !code) {
      return res.status(400).json({ error: "Token and code are required" });
    }

    const decoded = jwt.verify(tempToken, JWT_SECRET);
    if (!decoded.tempAccess) {
      return res.status(401).json({ error: "Invalid token" });
    }

    const user = await User.findById(decoded.id);
    if (!user || !user.twoFactorEmailCode) {
      return res.status(400).json({ error: "Invalid request" });
    }

    if (Date.now() > user.twoFactorEmailExpires) {
      return res.status(400).json({ error: "Code expired" });
    }

    const isValid = await bcrypt.compare(code, user.twoFactorEmailCode);
    if (!isValid) {
      return res.status(400).json({ error: "Invalid code" });
    }

    user.twoFactorEmailCode = null;
    user.twoFactorEmailExpires = null;
    await user.save();

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        department: user.department,
      },
    });
  } catch (error) {
    console.error("Verify email 2FA error:", error);
    res.status(500).json({ error: "Verification failed" });
  }
});

// ============================
// ROUTE: Resend email 2FA
// ============================
app.post("/auth/resend-email-2fa", async (req, res) => {
  try {
    const { tempToken } = req.body;

    if (!tempToken) {
      return res.status(400).json({ error: "Token required" });
    }

    const decoded = jwt.verify(tempToken, JWT_SECRET);
    if (!decoded.tempAccess) {
      return res.status(401).json({ error: "Invalid token" });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    user.twoFactorEmailCode = await bcrypt.hash(code, 10);
    user.twoFactorEmailExpires = Date.now() + 5 * 60 * 1000;
    await user.save();

    await sendEmail2FACode(user.email, code);

    res.json({ success: true, message: "Verification code resent" });
  } catch (error) {
    console.error("Resend email 2FA error:", error);
    res.status(500).json({ error: "Failed to resend code" });
  }
});

// ============================
// SERVE UPLOADED FILES STATICALLY
// ============================
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const PORT = process.env.PORT || 5001;
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`),
);
