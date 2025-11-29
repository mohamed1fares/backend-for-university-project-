const mongoose = require('mongoose');


const resultSchema = new mongoose.Schema({
    url:{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Url',
        required: true
    },
    vulnerability:{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Vulnerability',
        required: true
    },
    detected:{
        type: Boolean,
        required: true
    }
}, {timestamps: true});

module.exports = mongoose.model('Result', resultSchema);