const jwt = require('jsonwebtoken');
const error = require('../enums/errorCodes.cjs.js');

const LOG_MODE = 0; //0: NONE; 1: MINIMAL; 2: MEDIUM; 3: HIGH

const requestValidator = function(req, res, next) {
	let token = req.query.token || req.headers['x-access-token'];

	if (!token) {
		return res.status(401).json({ error: error("MISSING_TOKEN") })
	}

    if (LOG_MODE >= 2) console.log("Validating AuthToken before request forwarding: "+token)

	jwt.verify(token, process.env.JWT_SECRET, function(err, decoded) {			
		if (err){
    		if (LOG_MODE >= 2) console.warn("Error while validating token: "+err)
			res.status(403).json({ error: error("INVALID_TOKEN") })	
		}	
		else {
    		if (LOG_MODE >= 1) console.log("Decoded user from AuthToken: "+decoded)
			req.loggedUser = decoded;
			next();
		}
	});
};

module.exports = requestValidator