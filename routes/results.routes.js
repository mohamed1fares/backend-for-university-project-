const express = require('express');
const router = express.Router();
const {Result} = require('../controller/results.controller');
const {authenticate} = require('../middlewares/auth.middleware');


router.post('/result', authenticate, Result);

module.exports = router;