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
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

// استدعاء الموديلات
const Url = require('../model/url.model'); 
const Result = require('../model/results.model'); 
const Vulnerability = require('../model/vulnerability.model'); 

// --- 1. إعداد المسارات ---
const SCRIPTS_DIR = path.join(__dirname, '../vulnerabilityFiles'); 
const OUTPUT_DIR = path.join(__dirname, '../scan_results');
const TEMP_DIR = path.join(__dirname, '../temp_payloads');

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
        options: { non_destructive: true }
    };
    fs.writeFileSync(filePath, JSON.stringify(taskData, null, 2));
    return filePath;
}

function runScriptWorker(scriptFullPath, payloadPath) {
    return new Promise((resolve) => {
        console.log(`[Debug] Checking if file exists: ${scriptFullPath}`); // 1. تأكد من المسار

        if (!fs.existsSync(scriptFullPath)) {
            console.error(`[Error] Script file NOT found at: ${scriptFullPath}`);
            return resolve({ error: "Script file missing", vulnerable: false });
        }

        const command = "python"; // تأكد إنها python أو python3 حسب جهازك
        const python = spawn(command, ['-u', scriptFullPath, '--payload', payloadPath, '--outdir', OUTPUT_DIR]);
        
        let outputData = '';
        let errorData = '';

        // 2. نشوف المخرجات وهي طالعة
        python.stdout.on('data', (data) => { 
            const str = data.toString();
            console.log(`[Python Output]: ${str}`); 
            outputData += str; 
        });

        // 3. نشوف لو فيه أخطاء في البايثون
        python.stderr.on('data', (err) => { 
            const str = err.toString();
            console.error(`[Python Error]: ${str}`); 
            errorData += str;
        });

        python.on('close', (code) => {
            console.log(`[Debug] Python process closed with code: ${code}`);
            
            // تنظيف الملف المؤقت
            try { fs.unlinkSync(payloadPath); } catch (e) {} 

            // لو كان فيه خطأ في تشغيل السكريبت (Syntax Error مثلاً)
            if (code !== 0 && errorData.length > 0) {
                console.log("[Debug] Script failed execution.");
                return resolve({ error: errorData, vulnerable: false });
            }

            try {
                // محاولة قراءة الـ JSON
                const firstBrace = outputData.indexOf('{');
                const lastBrace = outputData.lastIndexOf('}');
                
                if (firstBrace !== -1 && lastBrace !== -1) {
                    const jsonStr = outputData.substring(firstBrace, lastBrace + 1);
                    const parsed = JSON.parse(jsonStr);
                    console.log("[Debug] Parsed JSON successfully:", parsed);
                    resolve(parsed);
                } else {
                    console.log("[Debug] No valid JSON found in output.");
                    resolve({ error: "No JSON output", vulnerable: false });
                }
            } catch (e) {
                console.error("[Debug] Failed to parse JSON:", e.message);
                resolve({ error: "JSON Parse Error", vulnerable: false });
            }
        });
    });
}

// --- 3. دالة الفحص الرئيسية (scanAll) ---

exports.scanAll = async (req, res) => {
    try {
        const targetUrlString = req.body.url; 

        if (!targetUrlString) {
            return res.status(400).json({ message: "URL string is required in body" });
        }

        const urlDoc = await Url.findOne({ originalUrl: targetUrlString });

        if (!urlDoc) {
            return res.status(404).json({ message: "هذا الرابط غير موجود. يجب إضافته أولاً." });
        }

        const vulnerabilities = await Vulnerability.find({});

        if (vulnerabilities.length === 0) {
            return res.status(404).json({ message: "لا توجد ثغرات مسجلة للفحص." });
        }

        console.log(`[*] Starting scan for URL: ${targetUrlString}`);

        const scanPromises = vulnerabilities.map(async (vuln) => {
            
            // 1. تحديد اسم الملف
            // ملاحظة: تأكد أن اسم ملف XSS في الفولدر هو نفس اسم الثغرة في الداتابيز
            // مثلاً لو الثغرة اسمها "Reflected XSS"، الملف لازم يكون "Reflected XSS.py"
            const scriptFileName = vuln.name.trim() + ".py"; 
            const scriptFullPath = path.join(SCRIPTS_DIR, scriptFileName);

            // 2. تجهيز البايلود
            const payloadPath = createTempPayload(targetUrlString, vuln._id);

            // 3. تشغيل السكريبت
            console.log(`[Running] Script: ${scriptFileName}`);
            const scriptResult = await runScriptWorker(scriptFullPath, payloadPath);

            // =========================================================
            // 4. منطق الاكتشاف (تم التحديث لدعم XSS script)
            // =========================================================
            let isDetected = false;

            if (scriptResult && typeof scriptResult === 'object') {
                
                // فحص الـ Summary (الأكثر شيوعاً)
                if (scriptResult.summary) {
                    // دعم SQL.py
                    if (scriptResult.summary.findings_count > 0) isDetected = true;
                }
                
                // دعم السكريبتات التي ترجع vulnerable: true مباشرة
                else if (scriptResult.vulnerable === true || scriptResult.is_vulnerable === true) {
                    isDetected = true;
                }
                
                // دعم السكريبتات التي ترجع مصفوفة findings مباشرة
                else if (Array.isArray(scriptResult.findings) && scriptResult.findings.length > 0) {
                    isDetected = true;
                }
            }

            console.log(`[Result] ${vuln.name} -> Detected: ${isDetected}`);

            const newResult = new Result({
                url: urlDoc._id,
                vulnerability: vuln._id,
                detected: isDetected
            });

            return newResult.save();
        });

        const savedResults = await Promise.all(scanPromises);

        return res.status(200).json({
            message: "Scan completed successfully",
            totalScanned: savedResults.length,
            results: savedResults
        });

    } catch (error) {
        console.error("Scan Error:", error);
        return res.status(500).json({ message: "Server Scan Error", error: error.message });
    }
};

// ... باقي دوال الـ GET (getResultsByUrl, getAllResults) كما هي ...
exports.getResultsByUrl = async (req, res) => {
    try {
        const { id } = req.params; 
        const results = await Result.find({ url: id }).populate("vulnerability", "name severity");
        res.status(200).json({ message: "Success", data: results });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

exports.getAllResults = async (req, res) => {
    try {
        const results = await Result.find().populate("vulnerability", "name");
        res.status(200).json(results);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};