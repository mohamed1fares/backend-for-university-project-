const rateLimit = require('express-rate-limit');

// 1. حماية صارمة لعمليات المصادقة (Login, Signup, OTP, Forgot Password)
// يسمح بـ 10 محاولات فقط كل 15 دقيقة
exports.authLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 دقيقة
	max: 10, // الحد الأقصى للمحاولات
	message: {
        message: " Too many attempts from this IP, please try again after 15 minutes."
    },
	standardHeaders: true, // يرجع معلومات الحد في الهيدر (RateLimit-Limit)
	legacyHeaders: false, // تعطيل الهيدر القديم
});

// 2. حماية خاصة لإرسال الإيميلات (عشان محدش يغرق السيرفر إيميلات)
// يسمح بـ 3 محاولات كل ساعة (لأن الإيميل مكلف)
exports.emailLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 ساعة
    max: 5, // 5 محاولات فقط
    message: {
        message: " Too many email requests. Please try again later."
    }
});