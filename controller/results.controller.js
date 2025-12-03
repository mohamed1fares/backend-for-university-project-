const Result = require('../model/results.model');
const Vulnerability = require('../model/vulnerability.model');


exports.Result = async (req, res) => {
    try {
        const { url, vulnerability } = req.body;

        if (!url || !vulnerability) {
            return res.status(400).json({
                message: "url and vulnerability are required"
            });
        }




        // 1) نجيب الـ vulnerability
        const vuln = await Vulnerability.findById(vulnerability)
            .select("isActive");
            if (!vuln) {
            return res.status(404).json({
                message: "Vulnerability not found"
            });
        }








        if (vuln.isActive) {



            
        //باقي كود طارق هنا
        //هنا انا كشفت اذا كانت الثغره تعمل ام لا  
        //ولو تعمل يبدا كود طارق التسيت عليها

        // لو طارق اكتشف ان الثغره شغاله يعمل 
        // detected: true 
        //detected: false






if(detected){

            // 2) نعمل result ونخزن فيه isActive
            const newResult = new Result({
                url,
                vulnerability,
                detected: true   // ← ← هنا أهم نقطة
            });



            const savedResult = await newResult.save();
            // 3) نحفظ

            // 4) نرجّع النتيجة مع populate
            const populated = await Result.findById(savedResult._id)
                .populate("vulnerability", "name severity isActive")
                .populate("url", "originalUrl");
    
            res.status(201).json({
                message: "Result created successfully",
                data: populated
            });
        }
        else{
            // 2) نعمل result ونخزن فيه isActive
            const newResult = new Result({
                url,
                vulnerability,
                detected: false   // ← ← هنا أهم نقطة
            });
            const savedResult = await newResult.save();
            // 3) نحفظ
        }
        // 4) نرجّع النتيجة مع populate
        const populated = await Result.findById(savedResult._id)
            .populate("vulnerability", "name severity isActive")
            .populate("url", "originalUrl");
        res.status(201).json({
            message: "Result created successfully",
            data: populated
        });
}



        else{
            res.status(400).json({
                message: "Vulnerability is not active",
                
            });
        }
        


    } catch (err) {
        res.status(500).json({
            message: "Failed to create result",
            error: err.message
        });
    }
};





exports.getResultsByUrl = async (req, res) => {
    try {
        const { id } = req.params;
        const results = await Result.find({ url: id })
            // .populate("vulnerability", "name severity isActive")
            // .populate("url", "originalUrl");
        res.status(200).json({
            message: "Results fetched successfully",
            data: results
        });
    } catch (err) {
        res.status(500).json({
            message: "Failed to fetch results",
            error: err.message
        });
        
    }
};





exports.getResults = async (req, res) => {
    try {
        const result = await Result.find()
        res.status(200).json(result);
    } catch (error) {
        res.status(500).json({ message: 'get URLs Error', error: error.message });
    }
}