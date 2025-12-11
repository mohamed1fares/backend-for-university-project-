const express = require('express');
const router = express.Router();
const { getUsers, editUser, getUserById, editUserStatus } = require('../controller/user.controller'); // createUser شلناها لاننا هنستخدم signup
const { login, signup, verifyAccount, resendOTP, forgotPassword, resetPassword } = require('../controller/auth.controller'); // استيراد الدوال الجديدة
const { authenticate } = require('../middlewares/auth.middleware');
const { authorize } = require('../middlewares/role.middelware');
const upload = require('../middlewares/uploads.middelware');
const { authLimiter, emailLimiter } = require('../middlewares/rateLimit.middleware');

// Login: محاولات تخمين الباسورد
router.post('/login', authLimiter, login);

// Signup: منع إنشاء حسابات وهمية بالجملة
router.post('/signup', authLimiter, upload.single('image'), signup); 

// Verify OTP: منع تخمين الكود
router.post('/verify', authLimiter, verifyAccount);

// Resend & Forgot: منع إغراق السيرفر بالإيميلات
router.post('/resend-otp', emailLimiter, resendOTP);
router.post('/forgot-password', emailLimiter, forgotPassword);

// Reset: منع تخمين الكود والباسورد
router.post('/reset-password', authLimiter, resetPassword);


// --- User Routes (كما هي) ---
router.get('/:id', authenticate, getUserById);
router.get('/', authenticate, authorize('admin'), getUsers);
router.put('/edit/:id', authenticate, editUser);
router.put('/edit/status/:id', authenticate, authorize('admin'), editUserStatus);

module.exports = router;