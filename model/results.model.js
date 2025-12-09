const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
    url: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Url',
        required: true
    },
    scanDate: {
        type: Date,
        default: Date.now
    },
    // ملخص سريع للتقرير
    summary: {
        totalVulnerabilities: { type: Number, default: 0 },
        highestSeverity: { 
            type: String, 
            enum: ['safe', 'Low', 'Medium', 'High', 'Critical'],
            default: 'safe'
        }
    },
    // مصفوفة تحتوي على تفاصيل كل ثغرة تم فحصها
    details: [
        {
            vulnerabilityId: { type: mongoose.Schema.Types.ObjectId, ref: 'Vulnerability' },
            vulnerabilityName: String, // تخزين الاسم لتسهيل العرض
            severity: String,
            isDetected: Boolean, // هل الثغرة موجودة أم لا
            technicalDetail: Object // هنا نخزن مخرجات البايثون (اختياري)
        }
    ]
}, { timestamps: true });


module.exports = mongoose.model('Report', reportSchema);