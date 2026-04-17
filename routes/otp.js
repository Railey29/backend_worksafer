const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const OTPVerification = require("../models/OTPVerification");
const { sendEmail2FACode } = require("../utils/mailer");

const JWT_SECRET = process.env.JWT_SECRET;

// ============================
// HELPER: Send OTP email using the unified mailer
// ============================
const sendOTPEmail = async (to, otp, isResend = false) => {
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      </head>
      <body style="margin:0;padding:0;background:#f4f4f5;font-family:'Segoe UI',Arial,sans-serif;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;padding:40px 0;">
          <tr>
            <td align="center">
              <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);">
                <tr>
                  <td style="background:#0f172a;padding:32px 40px;text-align:center;">
                    <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:700;letter-spacing:-0.5px;">WorkSAFER</h1>
                    <p style="margin:6px 0 0;color:#94a3b8;font-size:13px;">Workplace Safety Management</p>
                  </td>
                </tr>
                <tr>
                  <td style="padding:40px 40px 32px;">
                    <h2 style="margin:0 0 12px;color:#0f172a;font-size:20px;font-weight:600;">
                      ${isResend ? "Here's your new code" : "Verify your email"}
                    </h2>
                    <p style="margin:0 0 28px;color:#64748b;font-size:15px;line-height:1.6;">
                      Use the code below to verify your email address and complete your WorkSAFER registration.
                      This code expires in <strong>10 minutes</strong>.
                    </p>
                    <div style="background:#f8fafc;border:2px dashed #e2e8f0;border-radius:10px;padding:24px;text-align:center;margin-bottom:28px;">
                      <p style="margin:0 0 8px;color:#94a3b8;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:1px;">Verification Code</p>
                      <p style="margin:0;color:#0f172a;font-size:42px;font-weight:800;letter-spacing:10px;font-family:'Courier New',monospace;">${otp}</p>
                    </div>
                    <p style="margin:0;color:#94a3b8;font-size:13px;line-height:1.6;">
                      If you didn't request this code, you can safely ignore this email.
                    </p>
                  </td>
                </tr>
                <tr>
                  <td style="background:#f8fafc;padding:20px 40px;border-top:1px solid #e2e8f0;">
                    <p style="margin:0;color:#94a3b8;font-size:12px;text-align:center;">
                      &copy; ${new Date().getFullYear()} WorkSAFER. All rights reserved.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
  `;

  // Use the same mailer as 2FA (works with Resend on Railway)
  const { Resend } = require("resend");
  const nodemailer = require("nodemailer");

  const isProduction = process.env.NODE_ENV === "production";

  if (isProduction && process.env.RESEND_API_KEY) {
    const resend = new Resend(process.env.RESEND_API_KEY);
    await resend.emails.send({
      from: "WorkSAFER <onboarding@resend.dev>",
      to: [to],
      subject: isResend
        ? "Your New WorkSAFER Verification Code"
        : "Your WorkSAFER Verification Code",
      html: html,
    });
  } else {
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: `"WorkSAFER Security" <${process.env.EMAIL_USER}>`,
      to,
      subject: isResend
        ? "Your New WorkSAFER Verification Code"
        : "Your WorkSAFER Verification Code",
      html,
    });
  }
};

// ============================
// ROUTE: Send OTP to Email
// ============================
router.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    console.log(`📧 Send OTP request for: ${email}`);

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res
        .status(400)
        .json({ error: "A valid email address is required" });
    }

    // Check if email is already registered
    const User = require("../models/User");
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res
        .status(400)
        .json({ error: "An account with this email already exists" });
    }

    // Generate 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    console.log(`🔢 Generated OTP: ${otp}`);

    // Hash the OTP before storing
    const hashedOtp = await bcrypt.hash(otp, 10);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    // Upsert OTP record
    await OTPVerification.findOneAndUpdate(
      { email: email.toLowerCase() },
      {
        email: email.toLowerCase(),
        otp: hashedOtp,
        expiresAt,
        verified: false,
        attempts: 0,
      },
      { upsert: true, new: true },
    );

    // Send OTP via unified mailer
    await sendOTPEmail(email, otp);
    console.log(`✅ OTP sent to: ${email}`);

    res.json({
      success: true,
      message: "Verification code sent to your email",
      expiresInMinutes: 10,
    });
  } catch (error) {
    console.error("❌ Send OTP error:", error);
    res.status(500).json({
      error: "Failed to send verification code",
      details:
        process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
});

// ============================
// ROUTE: Verify OTP
// ============================
router.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ error: "Email and OTP are required" });
    }

    const enteredOtp = String(otp).trim();
    if (enteredOtp.length !== 6) {
      return res
        .status(400)
        .json({ error: "Please enter a valid 6-digit code" });
    }

    const otpRecord = await OTPVerification.findOne({
      email: email.toLowerCase(),
    });
    if (!otpRecord) {
      return res
        .status(400)
        .json({
          error: "No verification code found. Please request a new one.",
        });
    }

    if (Date.now() > otpRecord.expiresAt) {
      await OTPVerification.deleteOne({ email: email.toLowerCase() });
      return res
        .status(400)
        .json({
          error: "Verification code has expired. Please request a new one.",
        });
    }

    if (otpRecord.attempts >= 5) {
      await OTPVerification.deleteOne({ email: email.toLowerCase() });
      return res
        .status(429)
        .json({
          error: "Too many incorrect attempts. Please request a new code.",
        });
    }

    const isValid = await bcrypt.compare(enteredOtp, otpRecord.otp);
    if (!isValid) {
      await OTPVerification.findOneAndUpdate(
        { email: email.toLowerCase() },
        { $inc: { attempts: 1 } },
      );
      const remaining = 4 - otpRecord.attempts;
      return res.status(400).json({
        error: `Invalid verification code. ${remaining > 0 ? `${remaining} attempt${remaining !== 1 ? "s" : ""} remaining.` : "Please request a new code."}`,
      });
    }

    await OTPVerification.deleteOne({ email: email.toLowerCase() });

    const verifiedToken = jwt.sign(
      { email: email.toLowerCase(), emailVerified: true },
      JWT_SECRET,
      { expiresIn: "15m" },
    );

    res.json({
      success: true,
      message: "Email verified successfully",
      verifiedToken,
    });
  } catch (error) {
    console.error("Verify OTP error:", error);
    res.status(500).json({ error: "Verification failed" });
  }
});

// ============================
// ROUTE: Resend OTP
// ============================
router.post("/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const existing = await OTPVerification.findOne({
      email: email.toLowerCase(),
    });
    if (existing) {
      const createdAt = existing.createdAt || existing._id.getTimestamp();
      const secondsSinceCreated = (Date.now() - createdAt.getTime()) / 1000;
      if (secondsSinceCreated < 60) {
        const waitSeconds = Math.ceil(60 - secondsSinceCreated);
        return res.status(429).json({
          error: `Please wait ${waitSeconds} second${waitSeconds !== 1 ? "s" : ""} before requesting a new code`,
          waitSeconds,
        });
      }
    }

    const User = require("../models/User");
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res
        .status(400)
        .json({ error: "An account with this email already exists" });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const hashedOtp = await bcrypt.hash(otp, 10);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await OTPVerification.findOneAndUpdate(
      { email: email.toLowerCase() },
      {
        email: email.toLowerCase(),
        otp: hashedOtp,
        expiresAt,
        verified: false,
        attempts: 0,
        createdAt: new Date(),
      },
      { upsert: true, new: true },
    );

    await sendOTPEmail(email, otp, true);
    console.log(`✅ OTP resent to: ${email}`);

    res.json({
      success: true,
      message: "New verification code sent",
      expiresInMinutes: 10,
    });
  } catch (error) {
    console.error("Resend OTP error:", error);
    res.status(500).json({ error: "Failed to resend verification code" });
  }
});

module.exports = router;
