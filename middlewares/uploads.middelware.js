// middlewares/uploads.middelware.js
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const uploadsDir = path.join(__dirname, '..', 'uploads');

// تأكد أن المجلد موجود، وإلا أنشئه
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp'];
  if (!allowedExtensions.includes(ext)) {
    return cb(new Error('Only images are allowed (jpg, jpeg, png, webp)'), false);
  }
  cb(null, true);
};

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    // حفظ الاسم بدون backslash وغالبًا {timestamp}_{ext}
    const filename = `${Date.now()}${path.extname(file.originalname).toLowerCase()}`;
    cb(null, filename);
  }
});

const megaBytes = 1024 * 1024;
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 2 * megaBytes
  }
});

module.exports = upload;
