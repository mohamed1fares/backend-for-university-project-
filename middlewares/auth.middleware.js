const JWT =require('jsonwebtoken');
const User = require('../model/user.model.js')



exports.authenticate = async (req, res, next)=>{
    const authheader = req.headers.authorization
    if(!authheader || !authheader.startsWith('Bearer ')){
      return  res.status(401).json({message:"NO TOKEN PROVIDED"})
    }
    const token = authheader.split(' ')[1];
    try{
        const decoded = JWT.verify(token, process.env.JWT_KEY);
         const user = await User.findById(decoded.id).select('-password');
         req.user = user;
        //  console.log(user);
         
    }
    catch(error){
        return res.status(403).json({message:"INVALID TOKEN"})
    }

    // console.log(authheader);
    next();

}
