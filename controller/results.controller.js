// const Result = require('../model/results.model');
// const Vulnerability = require('../model/vulnerability.model');
// const {runDynamicScan}=require("./scan.controller")

// exports.Result = async (req, res) => {
//     try {
//         const { url, vulnerability } = req.body;

//         if (!url || !vulnerability) {
//             return res.status(400).json({
//                 message: "url and vulnerability are required"
//             });
//         }

//         // 1) نجيب الـ vulnerability
//         const vuln = await Vulnerability.findById(vulnerability)
//             .select("isActive");
//             if (!vuln) {
//             return res.status(404).json({
//                 message: "Vulnerability not found"
//             });
//         }

//         if (vuln.isActive) {

//         //باقي كود طارق هنا
//         //هنا انا كشفت اذا كانت الثغره تعمل ام لا
//         //ولو تعمل يبدا كود طارق التسيت عليها

//         // لو طارق اكتشف ان الثغره شغاله يعمل
//         // detected: true
//         //detected: false

// if(detected){

//             // 2) نعمل result ونخزن فيه isActive
//             const newResult = new Result({
//                 url,
//                 vulnerability,
//                 detected: true   // ← ← هنا أهم نقطة
//             });

//             const savedResult = await newResult.save();
//             // 3) نحفظ

//             // 4) نرجّع النتيجة مع populate
//             const populated = await Result.findById(savedResult._id)
//                 .populate("vulnerability", "name severity isActive")
//                 .populate("url", "originalUrl");

//             res.status(201).json({
//                 message: "Result created successfully",
//                 data: populated
//             });
//         }
//         else{
//             // 2) نعمل result ونخزن فيه isActive
//             const newResult = new Result({
//                 url,
//                 vulnerability,
//                 detected: false   // ← ← هنا أهم نقطة
//             });
//             const savedResult = await newResult.save();
//             // 3) نحفظ
//         }
//         // 4) نرجّع النتيجة مع populate
//         const populated = await Result.findById(savedResult._id)
//             .populate("vulnerability", "name severity isActive")
//             .populate("url", "originalUrl");
//         res.status(201).json({
//             message: "Result created successfully",
//             data: populated
//         });
// }

//         else{
//             res.status(400).json({
//                 message: "Vulnerability is not active",

//             });
//         }

//     } catch (err) {
//         res.status(500).json({
//             message: "Failed to create result",
//             error: err.message
//         });
//     }
// };

// exports.getResultsByUrl = async (req, res) => {
//     try {
//         const { id } = req.params;
//         const results = await Result.find({ url: id })
//             // .populate("vulnerability", "name severity isActive")
//             // .populate("url", "originalUrl");
//         res.status(200).json({
//             message: "Results fetched successfully",
//             data: results
//         });
//     } catch (err) {
//         res.status(500).json({
//             message: "Failed to fetch results",
//             error: err.message
//         });

//     }
// };

// exports.getResults = async (req, res) => {
//     try {
//         const result = await Result.find()
//         res.status(200).json(result);
//     } catch (error) {
//         res.status(500).json({ message: 'get URLs Error', error: error.message });
//     }
// }

// backend/controllers/resultController.js
const mongoose = require("mongoose");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");

// استدعاء الموديلات
const Url = require("../model/url.model");
const Result = require("../model/results.model");
const Vulnerability = require("../model/vulnerability.model");

// --- 1. إعداد المسارات ---
const SCRIPTS_DIR = path.join(__dirname, "../vulnerabilityFiles");
const OUTPUT_DIR = path.join(__dirname, "../scan_results");
const TEMP_DIR = path.join(__dirname, "../temp_payloads");

// إنشاء المجلدات لو مش موجودة
if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

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
    // 1. تأكد من وجود الملف
    if (!fs.existsSync(scriptFullPath)) {
      console.error(`[Error] Script file NOT found at: ${scriptFullPath}`);
      return resolve({ error: "Script file missing", vulnerable: false });
    }

    // 🔥 2. تحديد أمر البايثون حسب نظام التشغيل (حل مشكلة ENOENT)
    // لو ويندوز استخدم 'py' أو 'python'، لو غير كده استخدم 'python3'
    let command = "python3";

    if (process.platform === "win32") {
      try {
        execSync("py --version", { stdio: "ignore" });
        command = "py"; // لو py موجود
      } catch {
        command = "python"; // لو py مش موجود
      }
    }
    console.log(
      `[Debug] Spawning command: ${command} for file: ${path.basename(
        scriptFullPath
      )}`
    );

    const python = spawn(command, [
      "-u",
      scriptFullPath,
      "--payload",
      payloadPath,
      "--outdir",
      OUTPUT_DIR,
    ]);

    let outputData = "";
    let errorData = "";

    // تجميع المخرجات
    python.stdout.on("data", (data) => {
      outputData += data.toString();
    });
    python.stderr.on("data", (err) => {
      errorData += err.toString();
    });

    // منع توقف السيرفر لو البايثون نفسه فيه مشكلة تشغيل
    python.on("error", (err) => {
      console.error(`[Spawn Error] Failed to start Python: ${err.message}`);
      resolve({ error: "Python spawn failed", vulnerable: false });
    });

    python.on("close", (code) => {
      // تنظيف الملف المؤقت
      try {
        fs.unlinkSync(payloadPath);
      } catch (e) {}

      // لو في خطأ في الكود نفسه
      if (code !== 0 && errorData.length > 0) {
        console.log(`[Script Error Log]: ${errorData}`);
        // ملاحظة: أحياناً أدوات السكان بتطلع أخطاء بس بتطلع نتايج برضه، هنكمل محاولة البارس
      }

      try {
        // محاولة استخراج JSON من المخرجات
        const firstBrace = outputData.indexOf("{");
        const lastBrace = outputData.lastIndexOf("}");

        if (firstBrace !== -1 && lastBrace !== -1) {
          const jsonStr = outputData.substring(firstBrace, lastBrace + 1);
          const parsed = JSON.parse(jsonStr);
          resolve(parsed);
        } else {
          console.log(
            "[Debug] No valid JSON found. Raw Output:",
            outputData.substring(0, 100)
          ); // طباعة أول 100 حرف بس
          resolve({ error: "No JSON output", vulnerable: false });
        }
      } catch (e) {
        console.error("[Debug] JSON Parse Error:", e.message);
        resolve({ error: "JSON Parse Error", vulnerable: false });
      }
    });
  });
}

// --- 3. دالة الفحص الرئيسية (scanAll) ---

exports.scanAll = async (req, res) => {
  try {
    const { url } = req.body; // نأخذ الرابط من الـ body

    if (!url) {
      return res.status(400).json({ message: "URL is required" });
    }

    // 1. البحث عن الرابط في جدول Urls (أو إضافته لو مش موجود حسب المنطق بتاعك)
    // هنا سنفترض أنه يجب أن يكون موجوداً مسبقاً
    let urlDoc = await Url.findOne({ originalUrl: url });
    urlDoc.status='Scanning';
    
    if (!urlDoc) {
      // خيار: إما نرجع إيرور، أو ننشئه حالاً. هنا هنرجع إيرور للتوضيح
      return res
        .status(404)
        .json({ message: "URL needs to be added to the system first." });
    }

    // 2. جلب كل الثغرات المفعلة
    const vulnerabilities = await Vulnerability.find({ isActive: true });

    if (vulnerabilities.length === 0) {
      return res
        .status(404)
        .json({ message: "No active vulnerabilities found." });
    }

    console.log(
      `🚀 Starting Scan for: ${url} with ${vulnerabilities.length} scripts.`
    );

    // 3. تشغيل الفحص بالتوازي
    const scanPromises = vulnerabilities.map(async (vuln) => {
      // 🔥 نستخدم scriptFile المحفوظ في الداتا بيس لو موجود، أو نستخدم الاسم كاحتياطي
      // الأفضل دائماً الاعتماد على scriptFile عشان نتجنب مشاكل الأسماء
      let scriptFileName = vuln.scriptFile
        ? vuln.scriptFile
        : vuln.name.trim() + ".py";

        let severity_vuln= vuln.severity

      // تنظيف الاسم (لو المسار متخزن كامل في الداتا بيس، ناخد الاسم بس)
      scriptFileName = path.basename(scriptFileName);

      const scriptFullPath = path.join(SCRIPTS_DIR, scriptFileName);
      const payloadPath = createTempPayload(url, vuln._id);

      // تشغيل السكريبت
      const scriptResult = await runScriptWorker(scriptFullPath, payloadPath);

      // 4. تحديد هل الثغرة موجودة أم لا (Detection Logic)
      let isDetected = false;

      if (scriptResult && !scriptResult.error) {
        // منطق عام للكشف (SQLMap style, Generic style)
        if (scriptResult.summary && scriptResult.summary.findings_count > 0){
            isDetected = true;
            if(severity_vuln==='Critical'&&urlDoc.severity!=='Critical'){
              urlDoc.severity='Critical'
            }
            else if(severity_vuln==='High'){
              urlDoc.severity='High'
            }
            else if(severity_vuln==='Medium'){
              urlDoc.severity='Medium'
            }
            else if(severity_vuln==='Low'){
              urlDoc.severity='Low'
            }
            urlDoc.numberOfvuln=+1;
          urlDoc.status='Finished';

          }
        else if (scriptResult.vulnerable === true) {
          isDetected = true;
          if(severity_vuln==='Critical'){
            urlDoc.severity='Critical'
          }
          else if(severity_vuln==='High'){
            urlDoc.severity='High'
          }
          else if(severity_vuln==='Medium'){
            urlDoc.severity='Medium'
          }
          else if(severity_vuln==='Low'){
            urlDoc.severity='Low'
          }
          urlDoc.numberOfvuln=+1;
          urlDoc.status='Finished'


        }
        else if (
          Array.isArray(scriptResult.findings) &&
          scriptResult.findings.length > 0
        )
         { isDetected = true;
          if(severity_vuln==='Critical'){
            urlDoc.severity='Critical'
          }
          else if(severity_vuln==='High'){
            urlDoc.severity='High'
          }
          else if(severity_vuln==='Medium'){
            urlDoc.severity='Medium'
          }
          else if(severity_vuln==='Low'){
            urlDoc.severity='Low'
          }
          urlDoc.numberOfvuln=+1;
          urlDoc.status='Finished'

         }
      }else{
        urlDoc.status='Finished'
        urlDoc.severity='safe'
      }


      console.log(
        `📊 Result for ${vuln.name}: ${isDetected ? "DETECTED 🔴" : "Safe 🟢"}`
      );

      // 5. حفظ النتيجة في الداتا بيس (سواء كانت true أو false)
      const newResult = new Result({
        url: urlDoc._id,
        vulnerability: vuln._id,
        detected: isDetected,
        // scanDetails: scriptResult // ممكن تحفظ التفاصيل كاملة لو عندك حقل في الموديل
      });

      await urlDoc.save();


      return newResult.save();
    });

    // انتظار انتهاء جميع الفحوصات
    const savedResults = await Promise.all(scanPromises);

    // إرسال الرد للفرونت إند
    return res.status(200).json({
      message: "Scan completed successfully",
      target: url,
      results: savedResults,
    });
  } catch (error) {
    console.error("Scan Error:", error);
    return res
      .status(500)
      .json({ message: "Internal Server Error", error: error.message });
  }

};

// --- باقي دوال الـ GET ---
exports.getResultsByUrl = async (req, res) => {
  try {
    const { id } = req.params;
    const results = await Result.find({ url: id })
      .populate("vulnerability", "name severity description")
      .populate("url", "originalUrl");
    res.status(200).json({ message: "Success", data: results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }

};

exports.getAllResults = async (req, res) => {
  try {
    const results = await Result.find()
      .populate("vulnerability", "name")
      .populate("url", "originalUrl");
    res.status(200).json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
