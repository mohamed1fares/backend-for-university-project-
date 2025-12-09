const mongoose = require("mongoose");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");

// استدعاء الموديلات
const Url = require("../model/url.model");
const Report = require("../model/report.model"); // الموديل الجديد
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

function runScriptWorker(scriptFullPath, payloadPath) {
  return new Promise((resolve) => {
    if (!fs.existsSync(scriptFullPath)) {
      return resolve({ error: "Script file missing", vulnerable: false });
    }

    let command = process.platform === "win32" ? "py" : "python3";
    
    const python = spawn(command, [
      "-u", scriptFullPath, "--payload", payloadPath, "--outdir", OUTPUT_DIR
    ]);

    let outputData = "";
    
    python.stdout.on("data", (data) => { outputData += data.toString(); });
    python.stderr.on("data", (err) => console.error(`[Py Err]: ${err}`)); // Log errors only

    python.on("close", (code) => {
      try { fs.unlinkSync(payloadPath); } catch (e) {} // تنظيف

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
    const { url } = req.body;
    if (!url) return res.status(400).json({ message: "URL is required" });

    // 1. تجهيز الرابط وتحديث حالته
    let urlDoc = await Url.findOne({ originalUrl: url });
    if (!urlDoc) return res.status(404).json({ message: "URL needs to be added first." });

    urlDoc.status = 'Scanning';
    urlDoc.numberOfvuln = 0;
    urlDoc.severity = 'safe';
    await urlDoc.save();

    // 2. جلب الثغرات
    const vulnerabilities = await Vulnerability.find({ isActive: true });
    if (vulnerabilities.length === 0) {
      urlDoc.status = 'Finished';
      await urlDoc.save();
      return res.status(404).json({ message: "No active vulnerabilities found." });
    }

    console.log(`🚀 Starting Full Scan for: ${url}`);

    // 3. تشغيل الفحص بالتوازي (Parallel Execution)
    const scanPromises = vulnerabilities.map(async (vuln) => {
      let scriptFileName = vuln.scriptFile ? vuln.scriptFile : vuln.name.trim() + ".py";
      scriptFileName = path.basename(scriptFileName);
      
      const scriptFullPath = path.join(SCRIPTS_DIR, scriptFileName);
      const payloadPath = createTempPayload(url, vuln._id);

      // تشغيل السكريبت
      const scriptResult = await runScriptWorker(scriptFullPath, payloadPath);

      // منطق الاكتشاف
      let isDetected = false;
      if (scriptResult && !scriptResult.error) {
        if (scriptResult.summary && scriptResult.summary.findings_count > 0) isDetected = true;
        else if (scriptResult.vulnerable === true) isDetected = true;
        else if (Array.isArray(scriptResult.findings) && scriptResult.findings.length > 0) isDetected = true;
      }

      console.log(`Checking ${vuln.name}: ${isDetected ? "DETECTED 🔴" : "Safe 🟢"}`);

      // *تغيير جوهري:* هنا نرجع كائن بيانات بدلاً من الحفظ في قاعدة البيانات
      return {
        vulnerabilityId: vuln._id,
        vulnerabilityName: vuln.name,
        severity: vuln.severity,
        isDetected: isDetected,
        technicalDetail: scriptResult // نخزن نتيجة البايثون هنا للرجوع إليها
      };
    });

    // 4. تجميع كل النتائج في مصفوفة واحدة
    const resultsArray = await Promise.all(scanPromises);

    // 5. حساب الإحصائيات (العدد والخطورة القصوى)
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

    // 6. إنشاء وحفظ تقرير الفحص (Scan Report)
    const newReport = new Report({
        url: urlDoc._id,
        summary: {
            totalVulnerabilities: detectedCount,
            highestSeverity: finalSeverity
        },
        details: resultsArray // حفظنا المصفوفة الكاملة هنا
    });

    await newReport.save();

    // 7. تحديث حالة الرابط النهائية
    urlDoc.status = 'Finished';
    urlDoc.numberOfvuln = detectedCount;
    urlDoc.severity = detectedCount > 0 ? finalSeverity : 'safe';
    await urlDoc.save();

    return res.status(200).json({
      message: "Scan completed successfully",
      reportId: newReport._id, // نرجع رقم التقرير للفرونت
      summary: newReport.summary,
      results: resultsArray
    });

  } catch (error) {
    console.error("Scan Error:", error);
    if (req.body.url) {
        await Url.findOneAndUpdate({ originalUrl: req.body.url }, { status: 'Failed' });
    }
    return res.status(500).json({ message: "Internal Server Error", error: error.message });
  }
};

// --- 4. تحديث دوال جلب البيانات ---

// جلب كل التقارير لرابط معين (History)
exports.getReportsByUrl = async (req, res) => {
    try {
      const { id } = req.params; // هنا id هو الـ Url ID
      // بنجيب التقارير ونرتبها بالأحدث أولاً
      const reports = await Report.find({ url: id })
        .sort({ scanDate: -1 }) 
        .populate("url", "originalUrl");
        
      res.status(200).json({ message: "Success", data: reports });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
};

// جلب تفاصيل تقرير محدد (لما المستخدم يضغط على Show Details)
exports.getReportById = async (req, res) => {
    try {
        const { reportId } = req.params;
        const report = await Report.findById(reportId)
            .populate("url", "originalUrl");
            
        if (!report) return res.status(404).json({ message: "Report not found" });

        res.status(200).json({ data: report });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};