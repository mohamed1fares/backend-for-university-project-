const User = require("../model/user.model");
const bcrypt = require('bcrypt');
const logger = require('../utils/logger.utils');


exports.getUsers = async (req, res) => {
  try {
    const users = await User.find().select("-password -__v");

    res.status(200).json(users);
  } catch (error) {
    res
      .status(500)
      .json({ message: "failed to get users", error: error.message });
  }
};

exports.createUser = (role) => {
  return async (req, res) => {
    try {
      let {
        fristName,
        lastName,
        email,
        password,
        location,
        phone,
        age,
        nationalID
      } = req.body;

      // الصورة من Multer
      // const image = req.file ? req.file.path : null;
      let image = null;
      if (req.file) {
        // نحول المسار النسبي/الـ windows backslashes إلى forward slashes
        // خزن فقط الجزء بالنسبة للمجلد uploads عشان تبني URL في الفرانت بسهولة
        const fullPath = req.file.path.replace(/\\/g, '/'); // لعنصر التوافق على ويندوز
        // إذا أردت تخزين path بالنسبة للـ uploads فقط:
        const idx = fullPath.indexOf('/uploads/');
        image = idx !== -1 ? fullPath.slice(idx + 1) : `uploads/${req.file.filename}`;
      }
      const newUser = await User.create({
        fristName,
        lastName,
        email,
        password,
        location,
        phone,
        age,
        nationalID,
        image,
        role,
        userActive: 'notActive',
        userPending: 'pending'
      });

      // if (role === "admin") {
      //   newUser.isAdmin = true;
      //   await newUser.save();
      // }
      logger.info(`created user successfully: ${newUser.name}`);

      res.status(201).json({
        message: `${role} created successfully: ${newUser.name}`,
        data: newUser,
      });
    } catch (error) {
      res.status(500).json({
        message: `Failed creating user ${role}`,
        error: error.message,
      });
    }
  };
};

exports.editUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { fristName, lastName, location, phone, password, } = req.body;
    let updatedData = { fristName, lastName, location, phone };

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 12);
      updatedData.password = hashedPassword;
    }

    const updatedUser = await User.findByIdAndUpdate(id, updatedData, {
      new: true, // يرجع النسخة بعد التعديل
      runValidators: true, // يشغل الفاليديشن بتاع الموديل
    }).select("-password -__v");

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "User updated successfully",
      data: updatedUser,
    });
  } catch (error) {
    const { id } = req.params;
    const updatedUser = await User.findById(id).select("-password -__v");


    logger.warn(`Failed to update user: ${updatedUser.email} ; error is : ${error.message}`);

    res.status(500).json({
      message: "Failed to update user",
      error: error.message,
    });
  }
};



exports.editUserStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { userActive, userPending ,role,fristName} = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      id,
      { userActive, userPending ,role,fristName },
      {
        new: true,
        runValidators: true,
      }
    ).select("-password -__v");

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    logger.info(`User status updated successfully: ${fristName}`);

    res.status(200).json({
      message: "User status updated successfully",
      data: updatedUser,
    });
  } catch (error) {
    logger.warn(`Failed to update user status: ${error.message}`);

    res.status(500).json({
      message: "Failed to update user status",
      error: error.message,
    });
  }
};



exports.getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findById(id).select("-password -__v");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    // logger.info(`User retrieved successfully: ${user.name}`);

    res.status(200).json({
      message: "User retrieved successfully",
      data: user,
    });
  } catch (error) {
    const { id } = req.params;
    const user = await User.findById(id).select("-password -__v");

    logger.warn(`Failed to retrieve user: ${user.email} ; error is :${error.message}`);

    res.status(500).json({
      message: "Failed to retrieve user",
      error: error.message,
    });
  }
};




