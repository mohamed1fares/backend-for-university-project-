const express = require('express');
const router = express.Router();
const {postUrl,getUrls,addReportUrl,getUrlsById, getUrlsByUser} = require('../controller/url.controller'); 
const {authenticate} = require('../middlewares/auth.middleware');
const {authorize} = require('../middlewares/role.middelware');


router.get('/url', authenticate, getUrls);
router.post('/url', authenticate, postUrl);
router.put('/report', authenticate, authorize('admin'), addReportUrl);
router.get('/url/:id', authenticate, getUrlsById);
router.get('/user/urls', authenticate, getUrlsByUser);
module.exports = router;




// router.get('/url', getUrls);
// router.post('/url',  postUrl);
// router.put('/report', addReportUrl);
// router.get('/url/:id', getUrlsById);
// module.exports = router;