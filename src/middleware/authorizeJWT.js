const jwt = require('jsonwebtoken')

function authorizeJWT(req, res, next) {
    const token = req.headers.authorization

    if (!token) {
        return res.status(401).json({ message: 'Tidak Ada Token, Gagal Mengakses Fitur' })
    }

    try {
        const splitToken = token.split(' ')[1]
        const decoded = jwt.verify(splitToken, process.env.JWT_SECRET)
        req.userId = decoded.userId
        next()
    } catch (error) {
        return res.status(403).json({message: 'Gagal mengautentikasi token!'})
    }
}

module.exports = authorizeJWT