const multer = require("multer");
const path = require("path");

// مكان تخزين الملفات
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "vulnerabilityFiles"); // الفولدر اللي هيتحط فيه الملف
  },
  filename: (req, file, cb) => {
    const uniqueName =
      Date.now() + "-" + Math.round(Math.random() * 1e9) + path.extname(file.originalname);
    cb(null, uniqueName);
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
