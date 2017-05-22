const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

/* 
	USER MODEL
*/
const userSchema = new Schema({
	email: { type: String, unique: true, lowercase: true },
	password: String
});

/* 
	ENCRYPT PASSWORD
*/

// Before save event, run this function/hook
userSchema.pre('save', function(next) {
	// Point 'this' to the current instance of the user model
	const user = this;

	// Generate a salt, then run callback
	bcrypt.genSalt(10, function(err, salt) {
		if (err) {
			return next(err);
		}

		// Hash the password using the salt
		bcrypt.hash(user.password, salt, null, function(err, hash) {
			if (err) {
				return next(err);
			}
			// overwrite plain text password with encrypted version
			user.password = hash;
			next(); //then continue along as normal
		});
	});
});

/*
	COMPARE PASSWORDS FOR AUTHENTICATION
 */

userSchema.methods.comparePassword = function(candidatePassword, callback) {
	bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {

		if (err) {return callback(err);}

		callback(null, isMatch);
	});
};

const UserModelClass = mongoose.model('user', userSchema);

module.exports = UserModelClass;