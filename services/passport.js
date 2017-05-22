const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Create a local strategy
const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
	

	User.findOne({email: email}, function(err, user) {
		if (err) {return done(err);}

		if (!user) { return done(null, false);}

		// compare passwords

		user.comparePassword(password, function(err, isMatch) {
			if (err) {return done(err);}

			if (!isMatch) {return done(null, false);}

			return done(null, user);
		});
	});



});
// Set options for JWT strategy

const jwtOptions = {
	jwtFromRequest: ExtractJwt.fromHeader('authorization'),
	secretOrKey: config.secret
};

// Create JWT strategy

const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
	// See if user ID in payload exists in our database
	// If it does, call 'done' with that user
	// If not, call done without a user object

	User.findById(payload.sub, function(err, user) {
		if (err) {return done(err, false);}

		if (user) {
			done(null, user);
		}
		else {
			done(null, false);
		}
	});

});

// Tell passport to use the strategy

passport.use(jwtLogin);
passport.use(localLogin);