const express = require('express');
const router = express.Router();
const {Result,getResultsByUrl} = require('../controller/results.controller');
const {authenticate} = require('../middlewares/auth.middleware');

router.get('/:id',authenticate,getResultsByUrl)
router.post('/result', authenticate, Result);

module.exports = router;