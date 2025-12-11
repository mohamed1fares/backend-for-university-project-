const { createLogger, format, transports } = require('winston');
require('winston-mongodb'); 
require('dotenv').config(); // 🔥🔥 أهم سطر: تحميل المتغيرات هنا فوراً 🔥🔥

// تأكد أن الرابط موجود وإلا استخدم رابط افتراضي لتجنب توقف السيرفر
const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/test';

const logger = createLogger({
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    format: format.combine(
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        format.errors({ stack: true }),
        format.metadata(), 
        format.json()
    ),
    transports:[
        new transports.Console({
            format: format.simple() 
        }),
        new transports.File({ filename: 'logs/error.log', level: 'error' }),
        
        // 2. إضافة النقل للداتا بيس
        new transports.MongoDB({
            level: 'info', 
            db: mongoUri, // 🔥 الآن المتغير ده ليه قيمة ومسمعش
            options: { useUnifiedTopology: true },
            collection: 'audit_logs', 
            storeHost: true,
            capped: true, 
            cappedSize: 10000000, 
            metaKey: 'metadata' 
        })
    ]
});

module.exports = logger;