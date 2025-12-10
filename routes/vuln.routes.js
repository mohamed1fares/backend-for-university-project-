const express = require("express");
const router = express.Router();
const uploadVulnFile = require("../middlewares/uploadVulnFile.middleware");
const { addVulnerability,getVulnerabilities,getVulnerabilitiesById ,editVulnerability } = require("../controller/vuln.controller");
const {authenticate} = require('../middlewares/auth.middleware');
const {authorize} = require('../middlewares/role.middelware');




router.post("/", authenticate, authorize('admin'), uploadVulnFile, addVulnerability);
router.get("/", authenticate, getVulnerabilities);
router.post("/getByIds", authenticate, getVulnerabilitiesById); // new route
router.put("/:id", authenticate, authorize('admin'), uploadVulnFile, editVulnerability);






module.exports = router;