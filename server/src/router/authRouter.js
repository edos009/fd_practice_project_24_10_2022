const authRouter = require('express').Router();
const AuthController = require('../controllers/authController');

authRouter.post('/sign-in', AuthController.signIn);
authRouter.post('/sign-up', AuthController.signUp);
authRouter.post('/refresh', AuthController.refresh);

module.exports = authRouter;