const multer = require("multer");
const path = require("path");

// مكان تخزين الملفات
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "vulnerabilityFiles"); // مكان التخزين
  },
  filename: (req, file, cb) => {
    // تم التعديل هنا لاستخدام الاسم الأصلي للملف القادم من الطلب
    cb(null, file.originalname);
  },
});

// فلترة الملفات (نقبل .py فقط)
const fileFilter = (req, file, cb) => {
  if (file.originalname.endsWith(".py")) {
    cb(null, true);
  } else {
    cb(new Error("Only .py files are allowed"), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 3MB
});

module.exports = upload.single("scriptFile");
