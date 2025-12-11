const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  // 1. إعداد الناقل (Transporter)
  // ملاحظة: لو بتستخدم Gmail لازم تفعل "App Password" من إعدادات جوجل
  const transporter = nodemailer.createTransport({
    service: 'Gmail', // أو استخدم Host/Port لو عندك سيرفر خاص
    auth: {
      user: process.env.EMAIL_USERNAME, // ضيفهم في ملف .env
      pass: process.env.EMAIL_PASSWORD
    }
  });

  // 2. إعداد الرسالة
  const mailOptions = {
    from: 'VlunCraft Team <noreply@secuscan.com>',
    to: options.email,
    subject: options.subject,
    text: options.message,
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
        <h2 style="color: #4c6ef5;">Scan Completed Successfully!</h2>
        <p>Hello,</p>
        <p>${options.message}</p>
        <p>You can view the full detailed report on your dashboard.</p>
        <br>
        <a href="${options.link}" style="background: #4c6ef5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Report</a>
        <br><br>
        <p style="font-size: 12px; color: #777;">SecuScan Automated System</p>
      </div>
    `
  };

  // 3. إرسال
  await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;


