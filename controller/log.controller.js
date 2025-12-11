const Log = require('../model/log.model');

exports.getLogs = async (req, res) => {
    try {
        // 1. استقبال المعاملات من الرابط (Query Params)
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 25;
        const skip = (page - 1) * limit;
        const search = req.query.search || '';
        const level = req.query.level || 'all';

        // 2. بناء استعلام الفلترة
        let query = {};

        // فلترة بالبحث في الرسالة (Message)
        if (search) {
            query.message = { $regex: search, $options: 'i' };
        }

        // فلترة بالمستوى (Info, Error, etc.)
        if (level !== 'all') {
            query.level = level; // winston بيخزنها lowercase عادة
        }

        // 3. جلب البيانات والعدد الكلي
        const totalLogs = await Log.countDocuments(query);
        
        const logs = await Log.find(query)
            .sort({ timestamp: -1 }) // الأحدث أولاً
            .skip(skip)
            .limit(limit);
        
        // 4. إرسال الرد
        res.status(200).json({
            status: 'success',
            results: logs.length,
            totalLogs: totalLogs,
            totalPages: Math.ceil(totalLogs / limit),
            currentPage: page,
            data: logs
        });

    } catch (error) {
        res.status(500).json({ message: 'Error fetching logs', error: error.message });
    }
};