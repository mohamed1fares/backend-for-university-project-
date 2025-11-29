const User = require("../model/user.model");
const bcrypt = require('bcrypt');

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
      const image = req.file ? req.file.path : null;

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
        userActive: 'active',
        userPending: 'pending'
      });

      if (role === "admin") {
        newUser.isAdmin = true;
        await newUser.save();
      }
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
    res.status(500).json({
      message: "Failed to update user",
      error: error.message,
    });
  }
};



exports.editUserStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { userActive, userPending } = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      id,
      { userActive, userPending },
      {
        new: true,
        runValidators: true,
      }
    ).select("-password -__v");

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "User status updated successfully",
      data: updatedUser,
    });
  } catch (error) {
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
    res.status(200).json({
      message: "User retrieved successfully",
      data: user,
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to retrieve user",
      error: error.message,
    });
  }
};




