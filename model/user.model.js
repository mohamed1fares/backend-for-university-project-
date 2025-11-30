const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    fristName: { type: String, required: true,trim:true },
    lastName: { type: String, required: true, trim:true },
    
    email: { type: String, required: true, unique: true, trim:true,match: [/.+\@.+\..+/, 'Please fill a valid email address'],
        lowercase: true },

    password: { type: String, required: true ,minlength:6},
    
    role:{
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    // isAdmin: {
    //     type: Boolean,
    //     default: false
    // },
    location:{
        type: String,
        required: true,
        trim: true
    }
    ,
    phone:{
        type: String,
        required: true,
        minlength: 7
    },
    age:{
        type: Number,
        required: true,
        min: 0
    },
    nationalID:{
        type: Number,
        required: true,
        unique: true,
        minlength: 10,
    }
    ,
    image: {
        type: String,
        required: true
    },
    userActive:{
        type: String,
        enum: ['active', 'notActive'],
        default: 'notActive'
    },
    userPending:{
        type: String,
        enum: ['pending', 'accepted'],
        default: 'pending'
    },
    // url:{ type: String  , required: true

    // }

}, { timestamps: true });


userSchema.pre('save', async function () {
    if (!this.isModified('password')) return;

    this.password = await bcrypt.hash(this.password, 12);
});



userSchema.methods.correctPassword = async function(inputPassword) {
    return await bcrypt.compare(inputPassword, this.password);
}


module.exports = mongoose.model('User', userSchema);
