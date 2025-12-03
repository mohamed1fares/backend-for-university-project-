const express = require('express');
const router = express.Router();
const {createUser,getUsers,editUser,getUserById,editUserStatus} = require('../controller/user.controller');
const {login} = require('../controller/auth.controller');
const {authenticate} = require('../middlewares/auth.middleware');
const {authorize} = require('../middlewares/role.middelware');
const upload = require('../middlewares/uploads.middelware');

router.get('/:id', authenticate, getUserById);
router.get('/',authenticate, authorize('admin') ,getUsers);
router.post('/admin', createUser('admin'));
router.post('/user',  upload.single('image'),createUser('user'));
router.put('/edit/:id',authenticate, editUser);
router.put('/edit/status/:id', authenticate, authorize('admin'), editUserStatus);
router.post('/login', login);





module.exports = router;