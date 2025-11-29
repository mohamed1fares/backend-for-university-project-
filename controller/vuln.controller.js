const { log } = require("console");
const Vulnerability = require("../model/vulnerability.model");  

exports.addVulnerability = async (req, res) => {
  try {
    const {
      name,
      description,
      smallDescription,
      severity,
      isActive
      // urlID
    } = req.body;

    const scriptFile = req.file ? req.file.filename : null;

    const newVuln = await Vulnerability.create({
      name,
      description,
      smallDescription,
      severity,
      // urlID
      scriptFile,
      isActive
    });

    res.status(201).json({
      message: "Vulnerability created successfully",
      data: newVuln,
    });

  } catch (error) {
    res.status(500).json({
      message: "Error creating vulnerability",
      error: error.message,
    });
  }
};


exports.getVulnerabilities = async (req, res) => {
  try {
    const vulnerabilities = await Vulnerability.find();
    res.status(200).json({
      message: "Vulnerabilities fetched successfully",
      data: vulnerabilities,
    });
  } catch (error) {
    res.status(500).json({
      message: "Error fetching vulnerabilities",
      error: error.message,
    });
  }
};


exports.getVulnerabilitiesById = async (req, res) => {
  try {
    const { id } = req.params;
    const vulnerabilities = await Vulnerability.find({ _id: id });
    res.status(200).json({
      message: "Vulnerabilities fetched successfully",
      data: vulnerabilities,
    });
  }
  catch (error) {
    res.status(500).json({
      message: "Error fetching vulnerabilities",
      error: error.message,
    });
  }
};

exports.editVulnerability = async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    const updatedVuln = await Vulnerability.findByIdAndUpdate(id, updateData, { new: true });

    if (!updatedVuln) {
      return res.status(404).json({ message: "Vulnerability not found" });
    }
    res.status(200).json({
      message: "Vulnerability updated successfully",
      data: updatedVuln,
    });
  } catch (error) {
    res.status(500).json({
      message: "Error updating vulnerability",
      error: error.message,
    });
  }
};