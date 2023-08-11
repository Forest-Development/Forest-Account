"use strict";
exports.__esModule = true;
var express_1 = require("express");
var bodyParser = require("body-parser");
var cors = require('cors');
var useragent = require('express-useragent');
var _a = require("../middlewares/ErrorMiddleware"), handleError = _a.handleError, handleNotFound = _a.handleNotFound;
var userController = require("../controllers/UserController");
var userEmailNotificationController = require("../controllers/UserEmailNotificationController");
var userPasswordCodeController = require("../controllers/UserPasswordCodeController");
var userPasswordController = require("../controllers/UserPasswordController");
var userVerificationCodeController = require("../controllers/UserVerificationCodeController");
var userDeactivationCodeController = require("../controllers/UserDeactivationCodeController");
var userAuthenticationController = require("../controllers/UserAuthenticationController");
var userRoleController = require("../controllers/UserRoleController");
var userRouter = express_1.Router()
    .use("/users", userController)
    .use("/emailNotifications", userEmailNotificationController)
    .use("/passwordCodes", userPasswordCodeController)
    .use("/passwords", userPasswordController)
    .use("/verificationCodes", userVerificationCodeController)
    .use("/deactivationCodes", userDeactivationCodeController)
    .use("/auth", userAuthenticationController)
    .use("/roles", userRoleController);
var clientController = require("../controllers/ClientController");
var clientAuthorizationController = require("../controllers/ClientAuthorizationController");
var clientScopeController = require("../controllers/ClientScopeController");
var clientAllowedScopeController = require("../controllers/ClientAllowedScopeController");
var clientRouter = express_1.Router()
    .use("/clients", clientController)
    .use("/oauth", clientAuthorizationController)
    .use("/scopes", clientScopeController)
    .use("/allowedScopes", clientAllowedScopeController);
var permissionController = require("../controllers/PermissionController");
var permissionRouter = express_1.Router()
    .use("/permissions", permissionController);
var roleController = require("../controllers/RoleController");
var rolePermissionController = require("../controllers/RolePermissionController");
var roleRouter = express_1.Router()
    .use("/roles", roleController)
    .use("/permissions", rolePermissionController);
var scopeController = require("../controllers/ScopeController");
var scopePermissionController = require("../controllers/ScopePermissionController");
var scopeRouter = express_1.Router()
    .use("/scopes", scopeController)
    .use("/permissions", scopePermissionController);
var routes = express_1.Router()
    .use(bodyParser.json())
    .use(bodyParser.urlencoded({ extended: true }))
    .use(cors())
    .use(useragent.express())
    .use("/u", userRouter)
    .use("/c", clientRouter)
    .use("/p", permissionRouter)
    .use("/r", roleRouter)
    .use("/s", scopeRouter)
    .use(handleError)
    .use("*", handleNotFound);
exports["default"] = routes;
