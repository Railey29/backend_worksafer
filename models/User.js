const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: function () {
      return !this.googleId; // required only if googleId is NOT set
    },
    minlength: 6,
  },

  department: {
    type: String,
    required: true,
    enum: [
      "Safety Department",
      "Human Resources",
      "Quality Control",
      "Environmental",
      "Field Operations Group",
    ],
  },
  role: {
    type: String,
    default: null,
  },
  phoneNumber: {
    type: String,
    default: null,
  },
  picture: {
    type: String,
    default: null,
  },
  googleId: {
    type: String,
    default: null,
  },

  // Notification preferences
  notifications: {
    emailNotifications: { type: Boolean, default: true },
    smsAlerts: { type: Boolean, default: true },
    pushNotifications: { type: Boolean, default: false },
    incidentAlerts: { type: Boolean, default: true },
    complianceReminders: { type: Boolean, default: true },
    weeklyReports: { type: Boolean, default: false },
  },

  // 2FA Fields
  twoFactorEnabled: {
    type: Boolean,
    default: false,
  },
  // Application Settings
  settings: {
    language: {
      type: String,
      default: "en",
    },
    timeZone: {
      type: String,
      default: "Asia/Manila",
    },
    autoSaveReports: {
      type: Boolean,
      default: false,
    },
    dataSharing: {
      type: Boolean,
      default: false,
    },
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
  twoFactorEmailCode: {
    type: String,
    default: null,
  },
  twoFactorEmailExpires: {
    type: Date,
    default: null,
  },
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password") || !this.password) return next();

  // ✅ PREVENT DOUBLE HASHING
  if (this.password.startsWith("$2a$") || this.password.startsWith("$2b$")) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Method to check notification preferences
userSchema.methods.canSendEmail = function () {
  return this.notifications.emailNotifications;
};

userSchema.methods.canSendPush = function () {
  return this.notifications.pushNotifications;
};

// Virtual for full name to ensure backward compatibility
userSchema.virtual("name").get(function () {
  return `${this.firstName || ""} ${this.lastName || ""}`.trim();
});

// Ensure virtuals are included when converting to JSON
userSchema.set("toJSON", { virtuals: true });
userSchema.set("toObject", { virtuals: true });

module.exports = mongoose.model("User", userSchema);
