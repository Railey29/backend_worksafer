const nodemailer = require("nodemailer");
const { Resend } = require("resend");

// Detect if running on Railway (production)
const isProduction = process.env.NODE_ENV === "production";

let mailer;

if (isProduction && process.env.RESEND_API_KEY) {
  // Use Resend API on Railway
  mailer = "resend";
  console.log("✅ Using Resend API for email");
} else {
  // Use Gmail SMTP for local development
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  mailer = transporter;
  console.log("✅ Using Gmail SMTP for local email");
}

const sendEmail2FACode = async (to, code) => {
  try {
    const html = `
      <!DOCTYPE html>
      <html>
        <body style="margin:0;padding:0;background:#f4f4f5;font-family:Arial,sans-serif;">
          <div style="max-width:480px;margin:40px auto;background:#ffffff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,0.08);">
            <div style="background:#0f172a;padding:32px;text-align:center;border-radius:12px 12px 0 0;">
              <h1 style="margin:0;color:#ffffff;">WorkSAFER</h1>
            </div>
            <div style="padding:40px;">
              <h2 style="margin:0 0 12px;color:#0f172a;">Your 2FA Code</h2>
              <p style="margin:0 0 28px;color:#64748b;">Use this code to complete your login. It expires in 5 minutes.</p>
              <div style="background:#f8fafc;border:2px dashed #e2e8f0;border-radius:10px;padding:24px;text-align:center;">
                <p style="margin:0;color:#0f172a;font-size:42px;font-weight:800;letter-spacing:10px;">${code}</p>
              </div>
            </div>
          </div>
        </body>
      </html>
    `;

    if (mailer === "resend") {
      const resend = new Resend(process.env.RESEND_API_KEY);
      await resend.emails.send({
        from: "WorkSAFER <onboarding@resend.dev>",
        to: [to],
        subject: "Your 2FA Verification Code",
        html: html,
      });
    } else {
      await mailer.sendMail({
        from: `"WorkSAFER Security" <${process.env.EMAIL_USER}>`,
        to,
        subject: "Your 2FA Verification Code",
        html,
      });
    }

    console.log(`✅ 2FA email sent to: ${to}`);
  } catch (error) {
    console.error(`❌ Failed to send 2FA email:`, error);
    throw new Error("Failed to send 2FA email");
  }
};

const sendNotificationEmail = async (to, subject, message) => {
  try {
    if (mailer === "resend") {
      const resend = new Resend(process.env.RESEND_API_KEY);
      await resend.emails.send({
        from: "WorkSAFER <onboarding@resend.dev>",
        to: [to],
        subject: subject,
        html: `<p>${message}</p>`,
      });
    } else {
      await mailer.sendMail({
        from: `"WorkSAFER Notifications" <${process.env.EMAIL_USER}>`,
        to,
        subject,
        html: `<p>${message}</p>`,
      });
    }
    console.log(`✅ Notification sent to ${to}`);
  } catch (error) {
    console.error(`❌ Failed to send notification:`, error);
  }
};

module.exports = { sendEmail2FACode, sendNotificationEmail };
