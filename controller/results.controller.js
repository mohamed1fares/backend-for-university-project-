// const mongoose = require("mongoose");
// const path = require("path");
// const fs = require("fs");
// const { spawn, execSync } = require("child_process");
// const logger = require('../utils/logger.utils');
// const sendEmail = require('../utils/email.utils'); // استدعاء دالة الإيميل

// // استدعاء الموديلات
// const Url = require("../model/url.model");
// const Report = require("../model/results.model"); 
// const Vulnerability = require("../model/vulnerability.model");

// // --- 1. إعداد المسارات ---
// const SCRIPTS_DIR = path.join(__dirname, "../vulnerabilityFiles");
// const OUTPUT_DIR = path.join(__dirname, "../scan_results");
// const TEMP_DIR = path.join(__dirname, "../temp_payloads");

// // إنشاء المجلدات لو مش موجودة
// if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });
// if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

// // --- ترتيب خطورة الثغرات ---
// const SEVERITY_RANK = {
//   'safe': 0,
//   'Low': 1, 'low': 1,
//   'Medium': 2,
//   'High': 3,
//   'Critical': 4
// };

// // --- 2. دوال المساعدة (Helpers) ---

// // دالة لاكتشاف أمر البايثون المناسب (تعمل مرة واحدة)
// function getPythonCommand() {
//     const commandsToCheck = ['python3', 'python', 'py']; 
    
//     for (const cmd of commandsToCheck) {
//         try {
//             execSync(`${cmd} --version`, { stdio: 'ignore' });
//             return cmd; // لو اشتغل يرجع الأمر فوراً
//         } catch (error) {
//             continue;
//         }
//     }
//     // لو فشل في كله نرجع py كحل أخير للويندوز أو python3 للينكس
//     return process.platform === "win32" ? "py" : "python3";
// }

// function createTempPayload(targetUrl, vulnId) {
//   const filename = `payload_${vulnId}_${Date.now()}.json`;
//   const filePath = path.join(TEMP_DIR, filename);
//   const taskData = {
//     task_id: `scan-${vulnId}`,
//     target: { url: targetUrl },
//     base_url: targetUrl,
//     options: { non_destructive: true },
//   };
//   fs.writeFileSync(filePath, JSON.stringify(taskData, null, 2));
//   return filePath;
// }

// // دالة التشغيل (تم تعديلها لتستقبل pythonCmd)
// function runScriptWorker(scriptFullPath, payloadPath, pythonCmd) {
//   return new Promise((resolve) => {
//     if (!fs.existsSync(scriptFullPath)) {
//       return resolve({ error: "Script file missing", vulnerable: false });
//     }

//     // هنا كان سبب الخطأ عندك: التأكد من أن pythonCmd له قيمة
//     const cmd = pythonCmd || "python"; 

//     const python = spawn(cmd, [
//       "-u", scriptFullPath, "--payload", payloadPath, "--outdir", OUTPUT_DIR
//     ]);

//     let outputData = "";
    
//     python.stdout.on("data", (data) => { outputData += data.toString(); });
//     python.stderr.on("data", (err) => console.error(`[Py Log]: ${err}`)); 

//     python.on("error", (err) => {
//        console.error(`[Spawn Error]: ${err.message}`);
//        resolve({ error: "Spawn failed", vulnerable: false });
//     });

//     python.on("close", (code) => {
//       try { fs.unlinkSync(payloadPath); } catch (e) {} 

//       try {
//         const firstBrace = outputData.indexOf("{");
//         const lastBrace = outputData.lastIndexOf("}");
//         if (firstBrace !== -1 && lastBrace !== -1) {
//             const jsonStr = outputData.substring(firstBrace, lastBrace + 1);
//             resolve(JSON.parse(jsonStr));
//         } else {
//             resolve({ error: "No JSON output", vulnerable: false });
//         }
//       } catch (e) {
//         resolve({ error: "JSON Parse Error", vulnerable: false });
//       }
//     });
//   });
// }

// --- 3. دالة الفحص الرئيسية (scanAll) ---
// exports.scanAll = async (req, res) => {
//   try {
//     const { url } = req.body;
//     if (!url) return res.status(400).json({ message: "URL is required" });

//     let urlDoc = await Url.findOne({ originalUrl: url });
//     if (!urlDoc) return res.status(404).json({ message: "URL needs to be added first." });

//     // تحديث الحالة
//     urlDoc.status = 'Scanning';
//     urlDoc.numberOfvuln = 0;
//     urlDoc.severity = 'safe';
//     await urlDoc.save();

//     const vulnerabilities = await Vulnerability.find({ isActive: true });
//     if (vulnerabilities.length === 0) {
//       urlDoc.status = 'Finished';
//       await urlDoc.save();
//       return res.status(404).json({ message: "No active vulnerabilities found." });
//     }

//     // 🔥 1. تحديد البايثون مرة واحدة هنا
//     const pythonCommand = getPythonCommand();
//     console.log(`🚀 Starting Scan using [${pythonCommand}] for: ${url}`);

//     // 2. تشغيل الفحص
//     const scanPromises = vulnerabilities.map(async (vuln) => {
//       // تصحيح اسم الملف والامتداد
//       let scriptFileName = vuln.scriptFile ? vuln.scriptFile : vuln.name.trim() + ".py";
//       scriptFileName = path.basename(scriptFileName);
      
//       const scriptFullPath = path.join(SCRIPTS_DIR, scriptFileName);
//       const payloadPath = createTempPayload(url, vuln._id);

//       // 🔥 تمرير pythonCommand للدالة هنا
//       const scriptResult = await runScriptWorker(scriptFullPath, payloadPath, pythonCommand);

//       let isDetected = false;
//       if (scriptResult && !scriptResult.error) {
//         if (scriptResult.summary && scriptResult.summary.findings_count > 0) isDetected = true;
//         else if (scriptResult.vulnerable === true) isDetected = true;
//         else if (Array.isArray(scriptResult.findings) && scriptResult.findings.length > 0) isDetected = true;
//       }

//       console.log(`Checking ${vuln.name}: ${isDetected ? "DETECTED 🔴" : "Safe 🟢"}`);

//       return {
//         vulnerabilityId: vuln._id,
//         vulnerabilityName: vuln.name,
//         severity: vuln.severity,
//         isDetected: isDetected,
//         technicalDetail: scriptResult 
//       };
//     });

//     const resultsArray = await Promise.all(scanPromises);

//     // 3. الحسابات النهائية
//     let detectedCount = 0;
//     let maxSeverityRank = 0;
//     let finalSeverity = 'safe';

//     resultsArray.forEach(item => {
//       if (item.isDetected) {
//         detectedCount++;
//         const currentRank = SEVERITY_RANK[item.severity] || 0;
//         if (currentRank > maxSeverityRank) {
//           maxSeverityRank = currentRank;
//           finalSeverity = item.severity === 'Low' ? 'low' : item.severity;
//         }
//       }
//     });

//     // 4. حفظ التقرير
//     const newReport = new Report({
//         url: urlDoc._id,
//         summary: {
//             totalVulnerabilities: detectedCount,
//             highestSeverity: finalSeverity
//         },
//         details: resultsArray
//     });

//     await newReport.save();

//     // 5. تحديث الـ URL
//     urlDoc.status = 'Finished';
//     urlDoc.numberOfvuln = detectedCount;
//     urlDoc.severity = detectedCount > 0 ? finalSeverity : 'safe';
//     await urlDoc.save();

//     logger.info(`Scan completed successfully: ${urlDoc.originalUrl}`);

//     return res.status(200).json({
//       message: "Scan completed successfully",
//       reportId: newReport._id,
//       summary: newReport.summary,
//       results: resultsArray
//     });

//   } catch (error) {
//     logger.warn(`Scan Error: ${error.message}`);
//     console.error("Scan Error:", error);
//     if (req.body.url) {
//         await Url.findOneAndUpdate({ originalUrl: req.body.url }, { status: 'Failed' });
//     }
//     return res.status(500).json({ message: "Internal Server Error", error: error.message });
//   }
// };






// // results.controller.js

// exports.scanAll = async (req, res) => {
//   try {
//     // 1. نستقبل ID الرابط بدلاً من الرابط النصي
//     const { urlId } = req.body; 

//     if (!urlId) {
//         return res.status(400).json({ message: "URL ID is required" });
//     }

//     // 2. البحث عن وثيقة الرابط باستخدام ID (هذا يضمن تحديث السجل الصحيح)
//     let urlDoc = await Url.findById(urlId);

//     if (!urlDoc) {
//       return res.status(404).json({ message: "URL document not found." });
//     }

//     // نستخرج الرابط النصي من الداتا بيس عشان نبعته للبايثون
//     const targetUrlString = urlDoc.originalUrl;

//     // تحديث الحالة لهذا السجل تحديداً
//     urlDoc.status = 'Scanning';
//     urlDoc.numberOfvuln = 0;
//     urlDoc.severity = 'safe';
//     await urlDoc.save();

//     const vulnerabilities = await Vulnerability.find({ isActive: true });
//     if (vulnerabilities.length === 0) {
//       urlDoc.status = 'Finished';
//       await urlDoc.save();
//       return res.status(404).json({ message: "No active vulnerabilities found." });
//     }

//     const pythonCommand = getPythonCommand();
//     console.log(`🚀 Starting Scan using [${pythonCommand}] for: ${targetUrlString} (ID: ${urlId})`);

//     // 3. تشغيل الفحص
//     const scanPromises = vulnerabilities.map(async (vuln) => {
//       let scriptFileName = vuln.scriptFile ? vuln.scriptFile : vuln.name.trim() + ".py";
//       scriptFileName = path.basename(scriptFileName);
      
//       const scriptFullPath = path.join(SCRIPTS_DIR, scriptFileName);
//       // نرسل الرابط النصي (targetUrlString) لملف البايثون
//       const payloadPath = createTempPayload(targetUrlString, vuln._id);

//       const scriptResult = await runScriptWorker(scriptFullPath, payloadPath, pythonCommand);

//       let isDetected = false;
//       if (scriptResult && !scriptResult.error) {
//         if (scriptResult.summary && scriptResult.summary.findings_count > 0) isDetected = true;
//         else if (scriptResult.vulnerable === true) isDetected = true;
//         else if (Array.isArray(scriptResult.findings) && scriptResult.findings.length > 0) isDetected = true;
//       }

//       console.log(`Checking ${vuln.name}: ${isDetected ? "DETECTED 🔴" : "Safe 🟢"}`);

//       return {
//         vulnerabilityId: vuln._id,
//         vulnerabilityName: vuln.name,
//         severity: vuln.severity,
//         isDetected: isDetected,
//         technicalDetail: scriptResult 
//       };
//     });

//     const resultsArray = await Promise.all(scanPromises);

//     // الحسابات النهائية
//     let detectedCount = 0;
//     let maxSeverityRank = 0;
//     let finalSeverity = 'safe';

//     resultsArray.forEach(item => {
//       if (item.isDetected) {
//         detectedCount++;
//         const currentRank = SEVERITY_RANK[item.severity] || 0;
//         if (currentRank > maxSeverityRank) {
//           maxSeverityRank = currentRank;
//           finalSeverity = item.severity === 'Low' ? 'low' : item.severity;
//         }
//       }
//     });

//     // 4. حفظ التقرير (نربطه بنفس الـ urlDoc._id)
//     const newReport = new Report({
//         url: urlDoc._id,
//         summary: {
//             totalVulnerabilities: detectedCount,
//             highestSeverity: finalSeverity
//         },
//         details: resultsArray
//     });

//     await newReport.save();

//     // 5. تحديث الـ URL
//     urlDoc.status = 'Finished';
//     urlDoc.numberOfvuln = detectedCount;
//     urlDoc.severity = detectedCount > 0 ? finalSeverity : 'safe';
//     await urlDoc.save();

//     logger.info(`Scan completed successfully for ID: ${urlDoc._id}`);

//     if (urlDoc.user && urlDoc.user.email) {
//       try {
//           const reportLink = `http://localhost:4200/result/${urlId}`; // رابط الفرونت
//           const message = `Great news! The security scan for ${urlDoc.originalUrl} has finished. We found ${detectedCount} issues.`;
          
//           await sendEmail({
//               email: urlDoc.user.email,
//               subject: '🔍 Scan Finished - Action Required',
//               message: message,
//               link: reportLink
//           });
//           console.log(`Email sent to ${urlDoc.user.email}`);
//       } catch (emailError) {
//           console.error("Failed to send email:", emailError.message);
//           // لن نوقف الرد، فقط نسجل الخطأ
//       }
//   }

//     return res.status(200).json({
//       message: "Scan completed successfully",
//       reportId: newReport._id,
//       summary: newReport.summary,
//       results: resultsArray
//     });

//   } catch (error) {
//     logger.warn(`Scan Error: ${error.message}`);
//     console.error("Scan Error:", error);
//     // في حالة الخطأ، نحدث السجل باستخدام الـ ID اللي معانا
//     if (req.body.urlId) {
//         await Url.findByIdAndUpdate(req.body.urlId, { status: 'Failed' });
//     }
//     return res.status(500).json({ message: "Internal Server Error", error: error.message });
//   }
// };







// // --- دوال الجلب ---
// exports.getReportsByUrl = async (req, res) => {
//     try {
//       const { id } = req.params; 
//       const reports = await Report.find({ url: id })
//         .sort({ scanDate: -1 }) 
//         .populate("url", "originalUrl");
//       res.status(200).json({ message: "Success", data: reports });
//     } catch (err) {
//       res.status(500).json({ error: err.message });
//     }
// };

// exports.getReportById = async (req, res) => {
//     try {
//         const { reportId } = req.params;
//         const report = await Report.findById(reportId).populate("url", "originalUrl"); 
//         if (!report) return res.status(404).json({ message: "Report not found" });
//         res.status(200).json({ data: report });
//     } catch (err) {
//         res.status(500).json({ error: err.message });
//     }
// };



// // ... (باقي الدوال في الأعلى)

// // --- دالة جديدة: جلب كل التقارير للإحصائيات ---
// exports.getAllReports = async (req, res) => {
//   try {
//     // 1. جلب كل التقارير
//     // 2. ترتيبها بالأحدث أولاً (sort)
//     // 3. عمل populate لبيانات الرابط (اختياري بس مفيد)
//     const reports = await Report.find()
//       .sort({ scanDate: -1 }) 
//       .populate("url", "originalUrl");

//     // إرجاع المصفوفة مباشرة (Array of Reports)
//     res.status(200).json(reports);

//   } catch (error) {
//     console.error("Error fetching all reports:", error);
//     res.status(500).json({ message: "Server Error", error: error.message });
//   }
// };



const mongoose = require("mongoose");
const path = require("path");
const fs = require("fs");
const { spawn, execSync } = require("child_process");
const logger = require('../utils/logger.utils'); // تأكد من وجوده أو احذفه لو مش عندك
const sendEmail = require('../utils/email.utils'); 

// استدعاء الموديلات
const Url = require("../model/url.model");
const Report = require("../model/results.model"); 
const Vulnerability = require("../model/vulnerability.model");

// --- 1. إعداد المسارات ---
const SCRIPTS_DIR = path.join(__dirname, "../vulnerabilityFiles");
const OUTPUT_DIR = path.join(__dirname, "../scan_results");
const TEMP_DIR = path.join(__dirname, "../temp_payloads");

// إنشاء المجلدات لو مش موجودة
if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

// --- ترتيب خطورة الثغرات ---
const SEVERITY_RANK = {
  'safe': 0,
  'Low': 1, 'low': 1,
  'Medium': 2,
  'High': 3,
  'Critical': 4
};

// --- 2. دوال المساعدة (Helpers) ---

function getPythonCommand() {
    const commandsToCheck = ['python3', 'python', 'py']; 
    for (const cmd of commandsToCheck) {
        try {
            execSync(`${cmd} --version`, { stdio: 'ignore' });
            return cmd; 
        } catch (error) { continue; }
    }
    return process.platform === "win32" ? "py" : "python3";
}

function createTempPayload(targetUrl, vulnId) {
  const filename = `payload_${vulnId}_${Date.now()}.json`;
  const filePath = path.join(TEMP_DIR, filename);
  const taskData = {
    task_id: `scan-${vulnId}`,
    target: { url: targetUrl },
    base_url: targetUrl,
    options: { non_destructive: true },
  };
  fs.writeFileSync(filePath, JSON.stringify(taskData, null, 2));
  return filePath;
}

function runScriptWorker(scriptFullPath, payloadPath, pythonCmd) {
  return new Promise((resolve) => {
    if (!fs.existsSync(scriptFullPath)) {
      return resolve({ error: "Script file missing", vulnerable: false });
    }

    const cmd = pythonCmd || "python"; 
    const python = spawn(cmd, [
      "-u", scriptFullPath, "--payload", payloadPath, "--outdir", OUTPUT_DIR
    ]);

    let outputData = "";
    
    python.stdout.on("data", (data) => { outputData += data.toString(); });
    python.stderr.on("data", (err) => console.error(`[Py Log]: ${err}`)); 

    python.on("error", (err) => {
       console.error(`[Spawn Error]: ${err.message}`);
       resolve({ error: "Spawn failed", vulnerable: false });
    });

    python.on("close", (code) => {
      try { fs.unlinkSync(payloadPath); } catch (e) {} 
      try {
        const firstBrace = outputData.indexOf("{");
        const lastBrace = outputData.lastIndexOf("}");
        if (firstBrace !== -1 && lastBrace !== -1) {
            const jsonStr = outputData.substring(firstBrace, lastBrace + 1);
            resolve(JSON.parse(jsonStr));
        } else {
            resolve({ error: "No JSON output", vulnerable: false });
        }
      } catch (e) {
        resolve({ error: "JSON Parse Error", vulnerable: false });
      }
    });
  });
}

// --- 3. دالة الفحص الرئيسية (scanAll) ---
exports.scanAll = async (req, res) => {
  try {
    const { urlId } = req.body; 

    if (!urlId) {
        return res.status(400).json({ message: "URL ID is required" });
    }

    // 🔥🔥 التعديل هنا: إضافة .populate('user') 🔥🔥
    let urlDoc = await Url.findById(urlId).populate('user');

    if (!urlDoc) {
      return res.status(404).json({ message: "URL document not found." });
    }

    const targetUrlString = urlDoc.originalUrl;

    // تحديث الحالة
    urlDoc.status = 'Scanning';
    urlDoc.numberOfvuln = 0;
    urlDoc.severity = 'safe';
    await urlDoc.save();

    const vulnerabilities = await Vulnerability.find({ isActive: true });
    if (vulnerabilities.length === 0) {
      urlDoc.status = 'Finished';
      await urlDoc.save();
      return res.status(404).json({ message: "No active vulnerabilities found." });
    }

    const pythonCommand = getPythonCommand();
    console.log(`🚀 Starting Scan using [${pythonCommand}] for: ${targetUrlString} (ID: ${urlId})`);

    // تشغيل الفحص
    const scanPromises = vulnerabilities.map(async (vuln) => {
      let scriptFileName = vuln.scriptFile ? vuln.scriptFile : vuln.name.trim() + ".py";
      scriptFileName = path.basename(scriptFileName);
      
      const scriptFullPath = path.join(SCRIPTS_DIR, scriptFileName);
      const payloadPath = createTempPayload(targetUrlString, vuln._id);

      const scriptResult = await runScriptWorker(scriptFullPath, payloadPath, pythonCommand);

      let isDetected = false;
      if (scriptResult && !scriptResult.error) {
        if (scriptResult.summary && scriptResult.summary.findings_count > 0) isDetected = true;
        else if (scriptResult.vulnerable === true) isDetected = true;
        else if (Array.isArray(scriptResult.findings) && scriptResult.findings.length > 0) isDetected = true;
      }

      console.log(`Checking ${vuln.name}: ${isDetected ? "DETECTED 🔴" : "Safe 🟢"}`);

      return {
        vulnerabilityId: vuln._id,
        vulnerabilityName: vuln.name,
        severity: vuln.severity,
        isDetected: isDetected,
        technicalDetail: scriptResult 
      };
    });

    const resultsArray = await Promise.all(scanPromises);

    // الحسابات النهائية
    let detectedCount = 0;
    let maxSeverityRank = 0;
    let finalSeverity = 'safe';

    resultsArray.forEach(item => {
      if (item.isDetected) {
        detectedCount++;
        const currentRank = SEVERITY_RANK[item.severity] || 0;
        if (currentRank > maxSeverityRank) {
          maxSeverityRank = currentRank;
          finalSeverity = item.severity === 'Low' ? 'low' : item.severity;
        }
      }
    });

    // حفظ التقرير
    const newReport = new Report({
        url: urlDoc._id,
        summary: {
            totalVulnerabilities: detectedCount,
            highestSeverity: finalSeverity
        },
        details: resultsArray
    });

    await newReport.save();

    // تحديث الرابط
    urlDoc.status = 'Finished';
    urlDoc.numberOfvuln = detectedCount;
    urlDoc.severity = detectedCount > 0 ? finalSeverity : 'safe';
    await urlDoc.save();

    if(logger && logger.info) logger.info(`Scan completed successfully for ID: ${urlDoc._id}`);
    
    // 🔥 إرسال الإيميل (الآن سيعمل لأن urlDoc.user ممتلئ بالبيانات) 🔥
    if (urlDoc.user && urlDoc.user.email) {
      try {
          const reportLink = `http://localhost:4200/result/${urlId}`; 
          const message = `Great news! The security scan for ${urlDoc.originalUrl} has finished. We found ${detectedCount} issues.`;
          
          await sendEmail({
              email: urlDoc.user.email,
              subject: '🔍 Scan Finished - Action Required',
              message: message,
              link: reportLink
          });
          console.log(`✅ Email sent to ${urlDoc.user.email}`);
      } catch (emailError) {
          console.error("❌ Failed to send email:", emailError.message);
      }
    } else {
        console.warn("⚠️ User email not found.");
    }

    return res.status(200).json({
      message: "Scan completed successfully",
      reportId: newReport._id,
      summary: newReport.summary,
      results: resultsArray
    });

  } catch (error) {
    if(logger && logger.warn) logger.warn(`Scan Error: ${error.message}`);
    console.error("Scan Error:", error);
    
    if (req.body.urlId) {
        await Url.findByIdAndUpdate(req.body.urlId, { status: 'Failed' });
    }
    return res.status(500).json({ message: "Internal Server Error", error: error.message });
  }
};

// --- دوال الجلب الإضافية ---

exports.getAllReports = async (req, res) => {
  try {
    const reports = await Report.find()
      .sort({ scanDate: -1 }) 
      .populate("url", "originalUrl");
    res.status(200).json(reports);
  } catch (error) {
    res.status(500).json({ message: "Server Error", error: error.message });
  }
};

exports.getReportsByUrl = async (req, res) => {
  try {
    const { id } = req.params; // هذا هو urlId
    const currentUserId = req.user._id; // معرف المستخدم الحالي من التوكن
    const currentUserRole = req.user.role; // دور المستخدم (للسماح للأدمن)

    // 1. أولاً: نجلب وثيقة الرابط لنفحص مالكها
    const urlDoc = await Url.findById(id);

    if (!urlDoc) {
        return res.status(404).json({ message: "URL not found" });
    }

    // 2. التحقق من الملكية (Authorization Check)
    // نسمح بالمرور في حالتين:
    // أ. المستخدم هو صاحب الرابط
    // ب. المستخدم هو أدمن (Admin)
    if (urlDoc.user.toString() !== currentUserId.toString() && currentUserRole !== 'admin') {
        return res.status(403).json({ message: "⛔ Access Denied: You do not own this resource." });
    }

    // 3. إذا عبر التحقق، نجلب التقارير
    const reports = await Report.find({ url: id })
      .sort({ scanDate: -1 }) 
      .populate("url", "originalUrl");
      
    res.status(200).json({ message: "Success", data: reports });

  } catch (err) {
    console.error("Get Reports Error:", err);
    res.status(500).json({ error: err.message });
  }
};

exports.getReportById = async (req, res) => {
    try {
        const { reportId } = req.params;
        const report = await Report.findById(reportId).populate("url", "originalUrl"); 
        if (!report) return res.status(404).json({ message: "Report not found" });
        res.status(200).json({ data: report });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};