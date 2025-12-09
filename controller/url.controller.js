const Url = require('../model/url.model');
const logger = require('../utils/logger.utils');


exports.postUrl = async (req, res) => {
    try {
        const { originalUrl, report } = req.body;
        const userId = req.user._id
        const newUrl = new Url({ originalUrl, report, user: userId});
        const savedUrl = await newUrl.save();
        logger.info(`Post URL successfully: ${originalUrl}`);

        res.status(201).json(savedUrl);
    } catch (error) {
        logger.warn(`Post URL Error: ${error.message}`);
        res.status(500).json({ message: 'post URL Error', error: error.message });
    }
};









//احطياطي لحد ما الهكر يظبط الملف النهائي
exports.addReportUrl = async (req, res) => {
    try {
        const { urlId, report } = req.body;
        const updatedUrl = await Url.findByIdAndUpdate(
            urlId,
            { report },
            { new: true }
        );
        logger.info(`add Report URL successfully: ${report}`);

        res.status(200).json(updatedUrl);
    } catch (error) {
        logger.warn(`add Report URL Error: ${error.message}`);
        res.status(500).json({ message: 'add Report URL Error', error: error.message });
    }
};





exports.getUrlsByUser = async (req, res) => {
    try {
        const userId = req.user._id;
        const urls = await Url.find({ user: userId }).populate('user', 'username email');
        res.status(200).json(urls);
    } catch (error) {
        res.status(500).json({ message: 'get URLs by User Error', error: error.message });
    }
};














exports.getUrls = async (req, res) => {
    try {
        const urls = await Url.find().populate('user', 'username email');
        res.status(200).json(urls);
    } catch (error) {
        res.status(500).json({ message: 'get URLs Error', error: error.message });
    }
}




exports.getUrlsById = async (req, res) => {
    try {
        const urlId = req.params.id;
        const url = await Url.findById(urlId).populate('user', 'username email');
        if (!url) {
            return res.status(404).json({ message: 'URL not found' });
        }
        res.status(200).json(url);
    } catch (error) {
        res.status(500).json({ message: 'get URL by ID Error', error: error.message });
    }
}
