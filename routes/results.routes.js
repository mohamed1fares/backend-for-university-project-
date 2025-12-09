
const express = require('express');
const router = express.Router();
const resultController = require('../controller/results.controller');
const {authenticate} = require('../middlewares/auth.middleware');
const {authorize} = require('../middlewares/role.middelware');

// بدء الفحص
router.post('/scan-all',  authenticate, resultController.scanAll);

router.get('/', authenticate, resultController.getAllReports);

// جلب تاريخ الفحوصات لرابط معين (History)
router.get('/url/:id/reports',authenticate, resultController.getReportsByUrl);



// جلب تفاصيل تقرير محدد (Details)
router.get('/report/:reportId',authenticate, resultController.getReportById);

module.exports = router;