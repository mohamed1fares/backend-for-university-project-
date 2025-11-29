const mongoose = require('mongoose');

const urlSchema = new mongoose.Schema({
    originalUrl: { type: String, required: true },
    report:{ type: String, trim: true },
    user:{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
}
,{
    timestamps: true
})




module.exports = mongoose.model('Url', urlSchema);