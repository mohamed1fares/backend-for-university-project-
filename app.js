const express =require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db.config');
const cors = require('cors');
const mongoose = require('mongoose');

dotenv.config();
const app = express();
app.use(express.json());
connectDB();
app.use(cors());


// const corsmiddleware = require(`./middelwares/cors.middelware`)
// app.use(corsmiddleware);

app.use('/api/users', require('./routes/user.routes'));
app.use('/api/urls', require('./routes/url.routes'));
app.use('/api/vuln', require('./routes/vuln.routes'));
app.use('/api/results', require('./routes/results.routes'));

app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
});