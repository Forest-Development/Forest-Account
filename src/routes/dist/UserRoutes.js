"use strict";
exports.__esModule = true;
var express_1 = require("express");
var userController = require("../controllers/UserController");
var userPasswordCodeController = require("../controllers/UserPasswordCodeController");
var userVerificationCodeController = require("../controllers/UserVerificationCodeController");
var userDeactivationCodeController = require("../controllers/UserDeactivationCodeController");
var userAuthenticationController = require("../controllers/UserAuthenticationController");
var userEmailNotificationController = require("../controllers/UserEmailNotificationController");
// const userRoleController = require("../controllers/UserRoleController");
var userRouter = express_1.Router()
    .use("/auth", userAuthenticationController)
    .use("/users", userController)
    .use("/deactivationCodes", userDeactivationCodeController)
    .use("/emailNotifications", userEmailNotificationController)
    .use("/passwordCodes", userPasswordCodeController)
    // .use("/roles", userRoleController)
    .use("/verificationCodes", userVerificationCodeController);
exports["default"] = userRouter;
