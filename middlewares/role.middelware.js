exports.authorize = (...allowedRoles) => {
    return (req,res,next) => {
        // console.log(req.user.role);
        
        if(!allowedRoles.includes(req.user.role)){
            // console.log(req.user.role,allowedRoles);
            return res.status(403).json({message: "access denied"});
        }

        next();
    }
} 