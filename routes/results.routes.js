// const express = require('express');
// const router = express.Router();
// const {Result,getResultsByUrl,getResults} = require('../controller/results.controller');
// const {authenticate} = require('../middlewares/auth.middleware');
// const {authorize} = require('../middlewares/role.middelware');


// // getResults

// router.get('/:id',authenticate,getResultsByUrl)
// router.get('/',authenticate,authorize('admin'),getResults)
// router.post('/result', authenticate, Result);

// module.exports = router;







// const express = require('express');
// const router = express.Router();
// const resultController = require('../controller/results.controller');
// const {authenticate} = require('../middlewares/auth.middleware');
// const {authorize} = require('../middlewares/role.middelware');

// // هذا هو الرابط الجديد للفحص الشامل
// // POST http://localhost:3000/api/results/scan-all
// router.post('/scan-all', resultController.scanAll);

// // الروابط القديمة للعرض
// router.get('/url/:id', authenticate,resultController.getResultsByUrl);
// router.get('/', authenticate,authorize('admin'),resultController.getAllResults);

// module.exports = router;    



const express = require('express');
const router = express.Router();
const resultController = require('../controller/results.controller');
const {authenticate} = require('../middlewares/auth.middleware');
const {authorize} = require('../middlewares/role.middelware');

// بدء الفحص
router.post('/scan-all', resultController.scanAll);

// جلب تاريخ الفحوصات لرابط معين (History)
router.get('/url/:id/reports', resultController.getReportsByUrl);

// جلب تفاصيل تقرير محدد (Details)
router.get('/report/:reportId', resultController.getReportById);

module.exports = router;