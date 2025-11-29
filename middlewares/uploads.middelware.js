const multer = require('multer');
const path = require('path');
const fileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp'];
    if(!allowedExtensions.includes(ext)){
        return cb(new Error('Only images are allowed (jpg, jpeg, png, webp)'), false);
    }

    cb(null, true);

}
const storage = multer.diskStorage({
    destination:function(req, file, cb) {
        cb(null, 'uploads/');
        
},
filename:function(req, file, cb) {
    cb(null, `${Date.now()}_${path.extname(file.originalname)}`) 
}

});


const megaBytes = 1024*1024;
const upload = multer({
    storage:storage,
    fileFilter,
    limits:{
        fileSize: 2*megaBytes
    }
});

module.exports = upload;