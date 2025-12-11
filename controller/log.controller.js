const Log = require('../model/log.model');

exports.getLogs = async (req, res) => {
    try {
        // نجيب آخر 100 لوج مثلاً، الأحدث أولاً
        const logs = await Log.find().sort({ timestamp: -1 }).limit(100);
        
        res.status(200).json({
            status: 'success',
            results: logs.length,
            data: logs
        });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching logs', error: error.message });
    }
};