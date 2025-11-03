// Import bcrypt untuk enkripsi password
const bcrypt = require("bcryptjs");

// Import jsonwebtoken untuk pembuatan token JWT
const jwt = require("jsonwebtoken");

// Import prisma client untuk berinteraksi dengan database
const prisma = require("../prisma/client");

// Fungsi login
const login = async (req, res) => {
  try {
    // Mencari pengguna berdasarkan email
    const user = await prisma.user.findFirst({
      where: { email: req.body.email },
      select: {
        id: true,
        name: true,
        email: true,
        password: true,
      },
    });

    // Jika pengguna tidak ditemukan
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Pengguna tidak ditemukan",
      });
    }

    // Membandingkan password
    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Password tidak valid",
      });
    }

    // Membuat token JWT
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // Hapus password dari respons
    const { password, ...userWithoutPassword } = user;

    // Respons sukses
    return res.status(200).json({
      meta: {
        success: true,
        message: "Login berhasil",
      },
      data: {
        user: userWithoutPassword,
        token,
      },
    });
  } catch (error) {
    console.error("Login Error:", error);
    return res.status(500).json({
      meta: {
        success: false,
        message: "Terjadi kesalahan di server",
      },
      errors: error.message,
    });
  }
};

// Mengekspor fungsi login
module.exports = { login };
