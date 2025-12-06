const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

// استدعاء الموديل الخاص بك
const Vulnerability = require('../model/vulnerability.model'); // تأكد من صحة المسار

// ⚠️ هام جداً: هذا المسار يجب أن يكون نفس المسار الذي يحفظ فيه Multer الملفات
const SCRIPTS_DIR = path.join(__dirname, '../vulnerabilityFiles'); 
// مسار حفظ النتائج والملفات المؤقتة
const OUTPUT_DIR = path.join(__dirname, '../scan_results');
const TEMP_DIR = path.join(__dirname, '../temp_payloads');

// التأكد من وجود المجلدات
if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

// --- دالة مساعدة 1: إنشاء ملف البايلود (JSON) ---
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

// --- دالة مساعدة 2: تشغيل السكربت ---
function runScriptWorker(scriptFullPath, payloadPath) {
    return new Promise((resolve) => {
        if (!fs.existsSync(scriptFullPath)) {
            return resolve({ error: "Script file missing on server" });
        }

        // تشغيل البايثون
        const python = spawn('python', [ // أو 'python3' حسب السيرفر
            '-u', 
            scriptFullPath, 
            '--payload', payloadPath, 
            '--outdir', OUTPUT_DIR
        ]);

        let outputData = '';
        
        python.stdout.on('data', (data) => { outputData += data.toString(); });
        python.stderr.on('data', (err) => { console.error(`[Script Error]: ${err}`); });

        python.on('close', (code) => {
            // حذف ملف البايلود المؤقت لتنظيف السيرفر
            try { fs.unlinkSync(payloadPath); } catch (e) {}

            // محاولة تحويل الناتج لـ JSON
            try {
                // البحث عن بداية ونهاية الـ JSON فقط (تجاهل أي نصوص طباعة أخرى)
                const firstBrace = outputData.indexOf('{');
                const lastBrace = outputData.lastIndexOf('}');
                
                if (firstBrace !== -1 && lastBrace !== -1) {
                    const jsonStr = outputData.substring(firstBrace, lastBrace + 1);
                    const jsonResult = JSON.parse(jsonStr);
                    resolve(jsonResult);
                } else {
                    resolve({ error: "No JSON output detected", raw_output: outputData });
                }
            } catch (e) {
                resolve({ error: "Failed to parse JSON", raw_output: outputData });
            }
        });
    });
}

// --- الـ Middleware الرئيسي للفحص ---
exports.runDynamicScan = async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ success: false, message: "Target URL is required" });
    }

    try {
        console.log(`🚀 Starting Scan for: ${url}`);

        // 1. جلب الثغرات المفعلة والتي لها ملف سكربت فقط
        const vulnerabilities = await Vulnerability.find({ 
            isActive: true, 
            scriptFile: { $exists: true, $ne: null } 
        });

        if (vulnerabilities.length === 0) {
            return res.json({ success: false, message: "No active vulnerabilities found to scan." });
        }

        // 2. تشغيل السكربتات بالتوازي (Parallel Execution)
        const scanPromises = vulnerabilities.map(async (vuln) => {
            // تحديد مسار الملف بناءً على الاسم المحفوظ في الداتا بيس
            const scriptPath = path.join(SCRIPTS_DIR, vuln.scriptFile);
            
            // إنشاء بايلود خاص لهذه العملية
            const payloadPath = createTempPayload(url, vuln._id);

            // استدعاء دالة التشغيل
            const result = await runScriptWorker(scriptPath, payloadPath);

            // 3. تحليل بسيط للنتيجة (True/False logic)
            let isFound = false;
            if (result && result.summary && result.summary.findings_count > 0) isFound = true;
            if (result && Array.isArray(result.findings) && result.findings.length > 0) isFound = true;

            // إرجاع النتيجة مهيكلة
            return {
                vulnerability_id: vuln._id,
                name: vuln.name,
                severity: vuln.severity,
                description: vuln.smallDescription, // وصف قصير للعرض
                found: isFound,
                details: result // التفاصيل التقنية الكاملة من البايثون
            };
        });

        // انتظار انتهاء الجميع
        const results = await Promise.all(scanPromises);

        // إرسال الرد النهائي
        res.json({
            success: true,
            target: url,
            scanned_count: vulnerabilities.length,
            scan_date: new Date(),
            results: results
        });

    } catch (error) {
        console.error("Scan Error:", error);
        res.status(500).json({ success: false, error: error.message });
    }
};