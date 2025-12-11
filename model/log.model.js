const mongoose = require('mongoose');

// تعريف الـ Schema عشان نعرف نقراها بس (Winston هو اللي بيكتبها)
const logSchema = new mongoose.Schema({
    level: String,
    message: String,
    timestamp: Date,
    meta: Object 
}, { collection: 'audit_logs' }); // نفس الاسم اللي في logger.utils

module.exports = mongoose.model('Log', logSchema);