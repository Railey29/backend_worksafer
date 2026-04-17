const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true, // true for port 465
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, // App Password
  },
});

// 2FA email function with try/catch
const sendEmail2FACode = async (to, code) => {
  try {
    await transporter.sendMail({
      from: `"Security Team" <${process.env.EMAIL_USER}>`,
      to,
      subject: "Your 2FA Verification Code",
      html: `
        <p>Your verification code is:</p>
        <h2>${code}</h2>
        <p>This code expires in 5 minutes.</p>
      `,
    });
    console.log(`2FA email sent to: ${to}`);
  } catch (error) {
    console.error(`Failed to send 2FA email to ${to}:`, error);
    throw new Error("Failed to send 2FA email"); // important: stop login if email fails
  }
};

// General notification email
const sendNotificationEmail = async (to, subject, message) => {
  try {
    await transporter.sendMail({
      from: `"WorkSAFER Notifications" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html: `<p>${message}</p>`,
    });
    console.log(`Notification email sent to ${to}`);
  } catch (error) {
    console.error(`Failed to send notification email to ${to}:`, error);
  }
};

module.exports = { sendEmail2FACode, sendNotificationEmail };
