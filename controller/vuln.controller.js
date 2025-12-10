const { log } = require("console");
const Vulnerability = require("../model/vulnerability.model"); 
const logger = require('../utils/logger.utils');
const fs = require('fs');  
const path = require('path');
const SCRIPTS_DIR = path.join(__dirname, '../vulnerabilityFiles');


exports.addVulnerability = async (req, res) => {
  try {
    const {
      name,
      description,
      smallDescription,
      severity,
      isActive
      // urlID
    } = req.body;

    const scriptFile = req.file ? req.file.filename : null;

    const newVuln = await Vulnerability.create({
      name,
      description,
      smallDescription,
      severity,
      // urlID
      scriptFile,
      isActive
    });
    logger.info(`Vulnerability created successfully: ${name}`);

    res.status(201).json({
      message: "Vulnerability created successfully",
      data: newVuln,
    });

  } catch (error) {
    logger.warn(`Error creating vulnerability: ${name}`);

    res.status(500).json({
      message: "Error creating vulnerability",
      error: error.message,
    });
  }
};


exports.getVulnerabilities = async (req, res) => {
  try {
    const vulnerabilities = await Vulnerability.find();
    res.status(200).json({
      message: "Vulnerabilities fetched successfully all of data",
      data: vulnerabilities,
    });
  } catch (error) {
    res.status(500).json({
      message: "Error fetching vulnerabilities",
      error: error.message,
    });
  }
};



exports.getVulnerabilitiesById = async (req, res) => {
  try {
    const ids = req.body.ids; // expecting an array of strings
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ message: "ids array required" });
    }
    const vulns = await Vulnerability.find({ _id: { $in: ids } });
    return res.json(vulns);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};


// exports.getVulnerabilitiesById = async (req, res) => {
//   try {
//     const { id } = req.params;
//     const vulnerabilities = await Vulnerability.find({ _id: id });
//     res.status(200).json({
//       message: "Vulnerabilities fetched successfully by id",
//       data: vulnerabilities,
//     });
//   }
//   catch (error) {
//     res.status(500).json({
//       message: "Error fetching vulnerabilities",
//       error: error.message,
//     });
//   }
// };

exports.editVulnerability = async (req, res) => {
  try {
    const { id } = req.params;
    
    // 1. البحث عن الثغرة القديمة أولاً عشان نعرف اسم الملف القديم
    const oldVuln = await Vulnerability.findById(id);

    if (!oldVuln) {
      return res.status(404).json({ message: "Vulnerability not found" });
    }

    let updateData = { ...req.body };

    // 2. هل قام المستخدم برفع ملف جديد؟
    if (req.file) {
      updateData.scriptFile = req.file.filename; 

      // 🔥🔥 3. حذف الملف القديم (تنظيف السيرفر) 🔥🔥
      if (oldVuln.scriptFile) {
        const oldFilePath = path.join(SCRIPTS_DIR, oldVuln.scriptFile);
        
        // التأكد إن الملف موجود فعلاً قبل محاولة حذفه
        if (fs.existsSync(oldFilePath)) {
            try {
                fs.unlinkSync(oldFilePath); // حذف الملف
                console.log(`🗑️ Old script deleted: ${oldVuln.scriptFile}`);
            } catch (err) {
                console.error(`❌ Failed to delete old script: ${err.message}`);
            }
        }
      }
    }

    // 4. تحديث البيانات في قاعدة البيانات
    const updatedVuln = await Vulnerability.findByIdAndUpdate(id, updateData, { new: true });

    logger.info(`Vulnerability updated successfully: ${updatedVuln.name}`);

    res.status(200).json({
      message: "Vulnerability updated successfully",
      data: updatedVuln,
    });

  } catch (error) {
    logger.warn(`Error updating vulnerability: ${error.message}`);
    res.status(500).json({
      message: "Error updating vulnerability",
      error: error.message,
    });
  }
};