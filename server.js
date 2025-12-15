const express = require("express");
const { Sequelize, DataTypes } = require("sequelize");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cors = require("cors");
const dotenv = require("dotenv");
const path = require("path");
const { v2: cloudinary } = require("cloudinary");

// Load environment variables
dotenv.config();

const app = express();

// ======================
// MIDDLEWARE
// ======================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ======================
// CLOUDINARY SETUP
// ======================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

console.log("☁️  Cloudinary configured with cloud:", process.env.CLOUDINARY_CLOUD_NAME);

// Upload to Cloudinary - FIXED FOR PDFs
const uploadToCloudinary = async (fileBuffer, fileName, mimeType) => {
  return new Promise((resolve, reject) => {
    // Configure upload based on file type
    let uploadOptions = {
      folder: "erode-pavadi-documents",
      public_id: fileName.replace(/\.[^/.]+$/, ""), // Remove extension
      access_mode: "public",
    };

    // For PDFs and documents - use 'raw' resource type for direct viewing
    if (mimeType === 'application/pdf' || 
        mimeType.includes('msword') || 
        mimeType.includes('document') ||
        mimeType.includes('spreadsheet')) {
      uploadOptions.resource_type = 'raw';
      uploadOptions.flags = 'attachment:false'; // Allow inline viewing
    } else {
      // For images and other files
      uploadOptions.resource_type = 'auto';
    }

    const uploadStream = cloudinary.uploader.upload_stream(
      uploadOptions,
      (error, result) => {
        if (error) {
          console.error("Cloudinary upload error:", error);
          reject(error);
        } else {
          console.log("✅ Cloudinary upload result:", {
            id: result.public_id,
            url: result.secure_url,
            type: result.resource_type
          });
          resolve(result);
        }
      }
    );
    uploadStream.end(fileBuffer);
  });
};

// Delete from Cloudinary
const deleteFromCloudinary = async (publicId) => {
  // Try deleting as different resource types
  try {
    await cloudinary.uploader.destroy(publicId, { resource_type: "raw" });
  } catch (e) {
    await cloudinary.uploader.destroy(publicId, { resource_type: "image" });
  }
};

// ======================
// DATABASE CONNECTION
// ======================
const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: "postgres",
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false,
    },
  },
  logging: false,
  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
});

const connectDB = async () => {
  try {
    await sequelize.authenticate();
    console.log("✅ PostgreSQL (Neon) Connected Successfully");
    await sequelize.sync({ alter: true });
    console.log("✅ Database tables synchronized");
  } catch (error) {
    console.error("❌ Database connection failed:", error.message);
    process.exit(1);
  }
};

// ======================
// DATABASE MODELS
// ======================

// User Model
const User = sequelize.define(
  "User",
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    role: {
      type: DataTypes.ENUM("admin"),
      defaultValue: "admin",
    },
    email: {
      type: DataTypes.STRING,
      allowNull: true,
      validate: {
        isEmail: true,
      },
    },
  },
  {
    timestamps: true,
    hooks: {
      beforeCreate: async (user) => {
        if (user.password) {
          const salt = await bcrypt.genSalt(10);
          user.password = await bcrypt.hash(user.password, salt);
        }
      },
      beforeUpdate: async (user) => {
        if (user.changed("password")) {
          const salt = await bcrypt.genSalt(10);
          user.password = await bcrypt.hash(user.password, salt);
        }
      },
    },
  }
);

User.prototype.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Document Model
const Document = sequelize.define(
  "Document",
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    title: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    originalName: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    fileSize: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    mimeType: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    cloudinaryId: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    cloudinaryUrl: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    secureUrl: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    isViewable: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
    isDownloadable: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    uploadedBy: {
      type: DataTypes.UUID,
      allowNull: true,
    },
  },
  {
    timestamps: true,
  }
);

User.hasMany(Document, { foreignKey: "uploadedBy", as: "documents" });
Document.belongsTo(User, { foreignKey: "uploadedBy", as: "uploader" });

// ======================
// AUTH MIDDLEWARE
// ======================
const protect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return res.status(401).json({ message: "Not authorized, no token" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findByPk(decoded.id, {
      attributes: { exclude: ["password"] },
    });

    if (!req.user) {
      return res.status(401).json({ message: "User not found" });
    }

    next();
  } catch (error) {
    res.status(401).json({ message: "Not authorized, token failed" });
  }
};

// ======================
// MULTER CONFIG
// ======================
const storage = multer.memoryStorage();

const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /pdf|doc|docx|jpg|jpeg|png|xlsx|xls|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype =
      allowedTypes.test(file.mimetype) ||
      file.mimetype.includes("pdf") ||
      file.mimetype.includes("document") ||
      file.mimetype.includes("image") ||
      file.mimetype.includes("spreadsheet");

    if (extname || mimetype) {
      return cb(null, true);
    } else {
      cb(new Error("Only PDF, Word, Excel, and Image files are allowed"));
    }
  },
});

// ======================
// UTILITY
// ======================
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "30d" });
};

// ======================
// AUTH ROUTES
// ======================

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Please provide username and password" });
    }

    const userExists = await User.findOne({ where: { username } });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    const user = await User.create({
      username: username.toLowerCase(),
      password,
      email,
      role: "admin",
    });

    res.status(201).json({
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      token: generateToken(user.id),
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Please provide email and password" });
    }

    const user = await User.findOne({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      token: generateToken(user.id),
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ======================
// DOCUMENT ROUTES
// ======================

app.post("/api/documents/upload", protect, upload.single("file"), async (req, res) => {
  try {
    const { title, description, isViewable, isDownloadable } = req.body;

    if (!req.file) {
      return res.status(400).json({ message: "Please upload a file" });
    }

    if (!title) {
      return res.status(400).json({ message: "Please provide a title" });
    }

    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const fileName = uniqueSuffix + path.extname(req.file.originalname);

    console.log("📤 Uploading to Cloudinary:", fileName, "Type:", req.file.mimetype);

    // Upload to Cloudinary
    const cloudinaryResult = await uploadToCloudinary(
      req.file.buffer,
      fileName,
      req.file.mimetype
    );

    console.log("✅ Cloudinary upload success:", cloudinaryResult.public_id);

    const document = await Document.create({
      title,
      description,
      originalName: req.file.originalname,
      fileSize: req.file.size,
      mimeType: req.file.mimetype,
      cloudinaryId: cloudinaryResult.public_id,
      cloudinaryUrl: cloudinaryResult.url,
      secureUrl: cloudinaryResult.secure_url,
      isViewable: isViewable === "true" || isViewable === true,
      isDownloadable: isDownloadable === "true" || isDownloadable === true,
      uploadedBy: req.user.id,
    });

    res.status(201).json(document);
  } catch (error) {
    console.error("Upload error:", error.message);
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/documents", async (req, res) => {
  try {
    const documents = await Document.findAll({
      where: { isViewable: true },
      order: [["createdAt", "DESC"]],
    });
    res.json(documents);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/documents/admin", protect, async (req, res) => {
  try {
    const documents = await Document.findAll({
      include: [
        {
          model: User,
          as: "uploader",
          attributes: ["id", "username", "email"],
        },
      ],
      order: [["createdAt", "DESC"]],
    });
    res.json(documents);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/documents/:id", async (req, res) => {
  try {
    const document = await Document.findByPk(req.params.id);

    if (!document) {
      return res.status(404).json({ message: "Document not found" });
    }

    if (!document.isViewable) {
      return res.status(403).json({ message: "This document is not viewable" });
    }

    res.json(document);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.put("/api/documents/:id", protect, async (req, res) => {
  try {
    const { title, description, isViewable, isDownloadable } = req.body;
    const document = await Document.findByPk(req.params.id);

    if (!document) {
      return res.status(404).json({ message: "Document not found" });
    }

    if (title !== undefined) document.title = title;
    if (description !== undefined) document.description = description;
    if (isViewable !== undefined) document.isViewable = isViewable;
    if (isDownloadable !== undefined) document.isDownloadable = isDownloadable;

    await document.save();
    res.json(document);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.delete("/api/documents/:id", protect, async (req, res) => {
  try {
    const document = await Document.findByPk(req.params.id);

    if (!document) {
      return res.status(404).json({ message: "Document not found" });
    }

    if (document.cloudinaryId) {
      try {
        await deleteFromCloudinary(document.cloudinaryId);
        console.log("✅ Deleted from Cloudinary:", document.cloudinaryId);
      } catch (error) {
        console.error("Cloudinary delete error:", error.message);
      }
    }

    await document.destroy();
    res.json({ message: "Document deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ======================
// HEALTH CHECK
// ======================
app.get("/api/health", (req, res) => {
  res.json({
    message: "Erode Periya Pavadi Trust API is running",
    database: "PostgreSQL (Neon)",
    storage: "Cloudinary ✅",
    cloudName: process.env.CLOUDINARY_CLOUD_NAME,
    status: "OK",
    timestamp: new Date().toISOString(),
  });
});

app.get("/", (req, res) => {
  res.json({
    message: "Erode Periya Pavadi Trust - Document Management API",
    version: "1.0.0",
    storage: "Cloudinary",
    endpoints: {
      health: "/api/health",
      auth: {
        register: "POST /api/auth/register",
        login: "POST /api/auth/login",
      },
      documents: {
        list: "GET /api/documents",
        adminList: "GET /api/documents/admin",
        upload: "POST /api/documents/upload",
        get: "GET /api/documents/:id",
        update: "PUT /api/documents/:id",
        delete: "DELETE /api/documents/:id",
      },
    },
  });
});

// ======================
// ERROR HANDLING
// ======================
app.use((err, req, res, next) => {
  console.error("Server Error:", err.stack);
  res.status(500).json({ message: err.message || "Server Error" });
});

// ======================
// START SERVER
// ======================
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  console.log("🚀 Starting Erode Periya Pavadi Trust API...\n");
  await connectDB();

  app.listen(PORT, () => {
    console.log(`\n${"=".repeat(50)}`);
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📍 Local: http://localhost:${PORT}`);
    console.log(`📍 Health: http://localhost:${PORT}/api/health`);
    console.log(`💾 Database: Neon PostgreSQL ✅`);
    console.log(`☁️  Storage: Cloudinary (${process.env.CLOUDINARY_CLOUD_NAME}) ✅`);
    console.log(`${"=".repeat(50)}\n`);
  });
};

startServer();
