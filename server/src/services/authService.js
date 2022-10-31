const JwtService = require("./jwtService");
const { MAX_DEVICES_AMOUNT } = require("../constants");

module.exports.createSession = async (user) => {
  const tokenPair = await JwtService.createTokenPair(user);

  if ((await user.countRefreshTokens()) >= MAX_DEVICES_AMOUNT) {
    const oldestToken = await user.getRefreshTokens({
      order: [["updatedAt", "DESC"]],
    });
    await oldestToken.update({ value: tokenPair.refresh });
  } else {
    await user.createRefreshToken({ value: tokenPair.refresh });
  }

  return { user, tokenPair };
};

module.exports.refreshSession = async (refreshTokenInstance) => {
  const user = await refreshTokenInstance.getUser();

  const tokenPair = await JwtService.createTokenPair(user);

  await refreshTokenInstance.update({ value: tokenPair.refresh });

  return { user, tokenPair };
};
