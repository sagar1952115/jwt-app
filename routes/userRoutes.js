const express = require("express");
const authController = require("../controller/authController");
const userController = require("../controller/userController");

const router = express.Router();

router.post("/signup", authController.signup);
router.post("/login", authController.login);
router.post("/verifyEmail", authController.verifyEmail);
router.post("/forgotPassword", authController.forgotPassword);
router.patch("/resetPassword/:token", authController.resetPassword);


router.get("/", authController.protect, userController.getUser);
router.patch(
  "/follow/:id",
  authController.protect,
  userController.addFollowing,
  userController.follow
);
router.patch(
  "/unfollow/:id",
  authController.protect,
  userController.removeFollowing,
  userController.unfollow
);

module.exports = router;
