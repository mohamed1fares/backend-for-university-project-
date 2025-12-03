const express = require('express');
const router = express.Router();
const {Result,getResultsByUrl,getResults} = require('../controller/results.controller');
const {authenticate} = require('../middlewares/auth.middleware');
const {authorize} = require('../middlewares/role.middelware');


// getResults

router.get('/:id',authenticate,getResultsByUrl)
router.get('/',authenticate,authorize('admin'),getResults)
router.post('/result', authenticate, Result);

module.exports = router;