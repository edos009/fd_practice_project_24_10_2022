const createHttpError = require("http-errors");
const { User, RefreshToken } = require("../models");
const { MAX_DEVICES_AMOUNT } = require("../constants");
const JwtService = require("../services/jwtService");

module.exports.signIn = async (req, res, next) => {
  try {
    const {
      body: { email, password },
    } = req;
    const user = await User.findOne({
      where: { email },
    });
    if (user && (await user.comparePassword(password))) {
      const tokenPair = await JwtService.createTokenPair(user);

      if ((await user.countRefreshTokens()) >= MAX_DEVICES_AMOUNT) {
        const oldestToken = await user.getRefreshTokens({
          order: [["updatedAt", "DESC"]],
        });
        await oldestToken.update({ value: tokenPair.refresh });
      } else {
        await user.createRefreshToken({ value: tokenPair.refresh });
      }
      return res.status(201).send({
        data: user,
        tokenPair,
      });
    }
    next(createHttpError(401, "Unauthorized"));
  } catch (error) {
    next(error);
  }
};

module.exports.signUp = async (req, res, next) => {
  try {
    const { body } = req;
    const user = await User.create(body);

    const tokenPair = await JwtService.createTokenPair(user);

    await user.createRefreshToken({ value: tokenPair.refresh });

    res.status(201).send({
      data: user,
      tokenPair,
    });
  } catch (error) {
    next(error);
  }
};

module.exports.refresh = async (req, res, next) => {
  try {
    const {
      body: { refreshToken },
    } = req;

    const refreshTokenInstance = await RefreshToken.findOne({
      where: {
        value: refreshToken,
      },
    });

    const user = await refreshTokenInstance.getUser();

    const tokenPair = await JwtService.createTokenPair(user);

    await refreshTokenInstance.update({ value: tokenPair.refresh });
    res.status(200).send({
      data: user,
      tokenPair,
    });
  } catch (error) {
    next(error);
  }
};
