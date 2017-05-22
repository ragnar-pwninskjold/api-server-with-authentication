const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
	const timestamp = new Date().getTime();
	return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signup = function(req, res, next) {

	const email = req.body.email;
	const password = req.body.password;

	// check to see if user exists

	User.findOne({ email: email }, function(err, existingUser) {

		console.log("existingUser: ", existingUser);

		if ( !email || !password ) {
			return res.status(422).send({'error': 'You must provide an email and a password'});
		}

		if (err) {
			return next(err);
		}
		// if they exist, return error
		if (existingUser) {
			return res.status(422).send({'error': 'Email already in use'});
		}


		// if they don't exist, create and save user

		const user = new User({
			email: email,
			password: password
		});

		user.save(function(err) {

			if (err) {return next(err);}

			// respond to request, telling them it was created

			res.json({token: tokenForUser(user)});
		});

	});

};


exports.signin = function(req, res, next) {
	// User has already been auth'd
	// Give them token

	res.send({token: tokenForUser(req.user)});
}