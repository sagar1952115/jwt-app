const { promisify } = require("util");
const jwt = require("jsonwebtoken");
const User = require("./../models/Users");
const Email = require("./../utils/email");
const otpGenerator = require("otp-generator");

const catchAsync = require("./../utils/catchAsync");
const AppError = require("./../utils/appError");

const OTP_CONFIG = {
  digits: true,
};

const OTP = otpGenerator.generate(4, OTP_CONFIG);

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  res.cookie("jwt", token, cookieOptions);

  user.password = undefined;

  res.status(statusCode).json({
    status: "success",
    token,
  });
};

exports.signup = async (req, res, next) => {
  const generatedOTP = OTP;

  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
    otp: generatedOTP,
  });
  const url = 0;
  await new Email(newUser, url, generatedOTP).sendWelcome();

  createSendToken(newUser, 201, res);
};

exports.login = async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.send(400).json({
      status: "fail",
      data: "Please provide email and password",
    });

    return next();
  }
  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await user.correctPassword(password, user.password))) {
    res.send(400).json({
      status: "fail",
      data: "Incorrect email or password",
    });

    return next();
  }

  createSendToken(user, 200, res);
};

exports.verifyEmail = async (req, res, next) => {
  const { email, otp } = req.body;
  const user = await User.findOne({ email }).select("+otp");
  if (!user) {
    res.status(400).json({
      status: "fail",
      message: "User with this email does not exist!",
    });
  }

  if (otp !== user.otp) {
    res.status(400).json({
      status: "fail",
      message: "Invalid or Wrong OTP",
    });
  }

  createSendToken(user, 201, res);
};

exports.forgotPassword = async (req, res, next) => {
  // 1: Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError("No user with this email address.", 404));
  }

  // 2: Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // 3: Send it to user's email
  try {
    const resetURL = `${req.protocol}://${req.get(
      "host"
    )}/api/users/resetPassword/${resetToken}`;
    await new Email(user, resetURL).sendPasswordReset();

    res.status(200).json({
      status: "success",
      message: "Token sent to email",
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError("there was an error sending the email"), 500);
  }
};

exports.resetPassword = async (req, res, next) => {
  // 1: Get user based on the token
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });
  // 2: If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError("Token is invalid or has expired", 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // 3: Log the user in, send JWT
  const token = signToken(user._id);

  res.status(200).json({
    status: "success",
    token,
  });
};

exports.protect = catchAsync(async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    return next(
      new AppError("You are not logged in! Please log in to get access.", 401)
    );
  }

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError(
        "The user belonging to this token does no longer exist.",
        401
      )
    );
  }

  req.user = currentUser;
  next();
});
