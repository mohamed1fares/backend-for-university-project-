const User = require('../model/user.model.js')
const jwt = require('jsonwebtoken')
const logger = require('../utils/logger.utils');

const signtoken = (user) => {
    return jwt.sign({id:user._id,role:user.role,name:user.name},process.env.JWT_KEY, { expiresIn: process.env.JWT_EXPIRES_IN } );
}


exports.login = async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({email: email});
    if(!user || !(await user.correctPassword(password))){
        // logger.error(`user try successfully: ${req.params.route}`);
        return res.status(401).json({message: "User email or password is incorrect"});

    }
    else{
        logger.info(`user login successfully: ${email}`);
        res.status(200).json({message: "User logged in successfully", token: signtoken(user)});
    }


}
