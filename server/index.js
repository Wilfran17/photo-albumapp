
const express = require('express');
const cors = require('cors');
const fileUpload = require('express-fileupload');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();
const PORT = 4000;
const SECRET_KEY = process.env.SECRET_KEY || 'your-secret-key-here';

// Middleware
app.use(cors());
app.use(express.json());
app.use(fileUpload({ createParentPath: true }));
app.use("/images", express.static(path.join(__dirname, "images")));

// JWT Middleware
const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers['x-access-token'];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      req.userId = decoded.userId;
      next();
    } catch (jwtError) {
      console.error('JWT verification error:', jwtError);
      return res.status(403).json({ error: 'Invalid token' });
    }
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(500).json({ error: 'Token verification failed', details: error.message });
  }
};

// Verify token endpoint
app.get("/verify-token", verifyToken, (req, res) => {
  res.json({ valid: true });
});

// Auth: Register
app.post("/register", async (req, res) => {
  const { email, password, fullName } = req.body;

  if (!email || !password || !fullName) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(400).json({ error: "Email already registered" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, password: hashed, fullName },
    });

    res.json({ success: true, user: { id: user.id, email: user.email, fullName: user.fullName } });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: "Registration failed", details: err.message });
  }
});

// Auth: Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "24h" });
    res.json({ token, user: { id: user.id, email: user.email, fullName: user.fullName } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: "Login failed", details: err.message });
  }
});

// Upload Image (Private per user)
app.post("/api/upload-picture", verifyToken, async (req, res) => {
  try {
    console.log('Upload request received:', {
      hasFile: !!req.files?.image,
      fileName: req.files?.image?.name,
      userId: req.userId
    });

    if (!req.files || !req.files.image) {
      console.error('No file in request');
      return res.status(400).json({ error: "No file uploaded" });
    }

    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!user) {
      console.error('User not found for upload:', req.userId);
      return res.status(404).json({ error: "User not found" });
    }

    // Create images directory if it doesn't exist
    const imagesDir = path.join(__dirname, "images");
    if (!fs.existsSync(imagesDir)) {
      fs.mkdirSync(imagesDir);
    }

    // Save file to images directory
    const file = req.files.image;
    const relativePath = path.join("images", file.name);
    const absolutePath = path.join(__dirname, relativePath);
    console.log('Saving file to:', absolutePath);
    
    // Ensure the file is saved correctly
    await new Promise((resolve, reject) => {
      file.mv(absolutePath, (err) => {
        if (err) {
          console.error('File save error:', err);
          reject(err);
        } else {
          resolve();
        }
      });
    });

    // Save to database with relative path
    const image = await prisma.image.create({
      data: {
        userId: req.userId,
        filename: file.name,
        filePath: relativePath,
      },
    });

    console.log('Image saved successfully:', image);
    res.json({ success: true, message: "Image uploaded successfully", image });
  } catch (err) {
    console.error("Upload error:", err);
    console.error("Error details:", err.stack);
    res.status(500).json({ error: "Failed to upload image", details: err.message });
  }
});

// Get user's pictures
app.get("/api/pictures", verifyToken, async (req, res) => {
  try {
    console.log('Fetching pictures for user:', req.userId);
    const pictures = await prisma.image.findMany({
      where: { userId: req.userId },
      select: {
        id: true,
        filename: true,
        filePath: true,
        createdAt: true
      },
      orderBy: { createdAt: 'desc' }
    });
    console.log('Found pictures:', pictures.length);
    res.json({ success: true, pictures });
  } catch (err) {
    console.error("Get pictures error:", err);
    console.error("Error details:", err.stack);
    res.status(500).json({ error: "Failed to fetch pictures", details: err.message });
  }
});

// Delete image endpoint
app.delete("/api/delete-picture/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.userId;

    console.log('Delete request for image:', id, 'by user:', userId);

    // First get the image to check ownership and get the file path
    const image = await prisma.image.findUnique({
      where: { id: parseInt(id) },
      select: {
        id: true,
        userId: true,
        filePath: true,
        filename: true
      }
    });

    if (!image) {
      console.error('Image not found:', id);
      return res.status(404).json({ error: "Image not found" });
    }

    if (image.userId !== userId) {
      console.error('Unauthorized delete attempt:', userId, 'tried to delete', id);
      return res.status(403).json({ error: "Not authorized to delete this image" });
    }

    // Delete the file from disk
    try {
      const absolutePath = path.join(__dirname, image.filePath);
      if (fs.existsSync(absolutePath)) {
        fs.unlinkSync(absolutePath);
        console.log('File deleted:', absolutePath);
      } else {
        console.log('File not found:', absolutePath);
      }
    } catch (err) {
      console.error('Error deleting file:', err);
    }

    // Delete from database
    try {
      await prisma.image.delete({
        where: { id: parseInt(id) }
      });
      console.log('Image record deleted:', id);
    } catch (err) {
      console.error('Error deleting database record:', err);
      throw err; // Re-throw to be caught by outer catch
    }

    res.json({ success: true, message: "Image deleted successfully" });
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ error: "Failed to delete image", details: err.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
