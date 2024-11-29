const jwt = require("jsonwebtoken");

const authorizePH = (req, res, next) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ message: "Token not provided" });
    }

    try {
        const splitToken = token.split(' ')[1]
        const decoded = jwt.verify(splitToken, process.env.JWT_SECRET);
        req.userId = decoded.userId; // tambahin ini
        if (decoded.role !== "PH_OPERATOR") {
            return res.status(403).json({ message: "Role WH is Unauthorized" });
        }
        next();
    } catch (error) {
        console.error("Authorization error:", error.message);
        return res.status(401).json({ message: "Invalid token" });
    }
};

module.exports = authorizePH;