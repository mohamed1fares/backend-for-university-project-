const mongoose = require('mongoose');

const urlSchema = new mongoose.Schema({
    originalUrl: { type: String, required: true },
    report:{ type: String, trim: true },
    user:{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    status:{
        type:String,
        enum:['UnScaned','Scanning','Finished','Failed'],
        default:'UnScaned'
    }
    ,
    severity:{
        type: String,
        enum: ['High', 'low', 'Medium', 'Critical','safe'],
        default: 'safe'
    },
    numberOfvuln:{
        type: Number,
        default: 0
    }
}

,{
    timestamps: true
})




module.exports = mongoose.model('Url', urlSchema);