// const express =require('express');
// const dotenv = require('dotenv');
// const connectDB = require('./config/db.config');
// const cors = require('cors');
// const mongoose = require('mongoose');

// dotenv.config();
// const app = express();
// app.use(express.json());
// connectDB();
// app.use(cors());


// // const corsmiddleware = require(`./middelwares/cors.middelware`)
// // app.use(corsmiddleware);

// app.use('/api/users', require('./routes/user.routes'));
// app.use('/api/urls', require('./routes/url.routes'));
// app.use('/api/vuln', require('./routes/vuln.routes'));
// app.use('/api/results', require('./routes/results.routes'));

// app.listen(process.env.PORT, () => {
//     console.log(`Server is running on port ${process.env.PORT}`);
// });


// server.js
const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db.config');
const cors = require('cors');
const path = require('path');

dotenv.config();

const app = express();

// body parser
app.use(express.json());

// CORS (تقدر تخصّص origin لو حبيت)
app.use(cors());

// serve uploads folder so images are reachable via:
// http://HOST:PORT/uploads/<filename>
const uploadsPath = path.join(__dirname, 'uploads');
app.use('/uploads', express.static(uploadsPath));

// routes
app.use('/api/users', require('./routes/user.routes'));
app.use('/api/urls', require('./routes/url.routes'));
app.use('/api/vuln', require('./routes/vuln.routes'));
app.use('/api/results', require('./routes/results.routes'));
// app.use('/api/scan', require('./routes/scan.routes'));


// basic error handler (so multer/file errors return nice message)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ message: err.message || 'Internal Server Error' });
});

// start server AFTER DB connected
const PORT = process.env.PORT || 3000;

(async () => {
  try {
    await connectDB(); // تأكد أن connectDB يعيد promise
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    //   console.log(`Serving uploads folder from: ${uploadsPath}`);
    });
  } catch (err) {
    console.error('Failed to connect DB, server not started:', err);
    process.exit(1);
  }
})();
