const express = require('express');
const router = express.Router();
const logController = require('../controller/log.controller');
const { authenticate } = require('../middlewares/auth.middleware');
const { authorize } = require('../middlewares/role.middelware');

// حماية الراوتر: الأدمن بس هو اللي يشوف الـ Logs
router.get('/', authenticate, authorize('admin'), logController.getLogs);

module.exports = router;