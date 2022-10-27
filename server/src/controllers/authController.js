const createHttpError = require('http-errors');
const { User } = require('../models');

module.exports.signIn = async (req, res, next) =>{
  try {
    const {body:{email, password}} = req;
    // find user by unique email
    const user = await User.findOne({
      where: {email}
    });
    // compare password (hash)
    if(user && await user.comparePassword(password)){
      // create token pair
      // send user with token
    }
    next(createHttpError(401, 'Unauthorized'));  
  } catch (error) {
    next(error)
  }
}

module.exports.signUp = async (req, res, next) =>{
  try {
    const {body} = req;
    const user = await User.create(body);
    
  } catch (error) {
    next(error)
  }
}

module.exports.refresh = async (req, res, next) =>{
  try {
    
  } catch (error) {
    next(error)
  }
}