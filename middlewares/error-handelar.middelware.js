const logger = require('../utils/logger.utils');
module.exports = (err,req,res,next) =>{
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';

    logger.error(`Error occured [${req.method} ||${req.originalUrl}
      ${err.message} ||stack :  ${err.stack}] || ${res.user?.id}
    ]`);



    if(process.env.NODE_ENV === 'development'){
        return res.status(err.statusCode).json({
            status: err.status,
            message: err.message,
            stack: err.stack,
            error: err
        })
    }



    return res.status(err.statusCode).json({
        status: err.status,
        message: err.message
    })


    //عشان تفهم الفكره بس
    // if(process.env.NODE_ENV === 'production'){
    //     if(err.isOperational){
    //         return res.status(err.statusCode).json({
    //             status: err.status,
    //             message: err.message
    //         })
    //     }
    // }



}