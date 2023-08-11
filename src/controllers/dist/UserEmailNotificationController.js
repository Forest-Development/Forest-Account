"use strict";
exports.__esModule = true;
var express_1 = require("express");
var _a = require("../middlewares/CheckMiddleware"), checkAuthorization = _a.checkAuthorization, checkPermissions = _a.checkPermissions, checkUserId = _a.checkUserId, checkBodyData = _a.checkBodyData, showMiddlewareData = _a.showMiddlewareData;
var UserEmailNotificationService_1 = require("../services/UserEmailNotificationService");
var UserEmailNotificationValidator_1 = require("../validators/UserEmailNotificationValidator");
var router = express_1["default"].Router();
router.post("/", checkAuthorization(["CLIENT_ACCESS_TOKEN"]), checkPermissions(["CREATE_ANY_USER_EMAIL_NOTIFICATION", "CREATE_OWN_USER_EMAIL_NOTIFICATION"]), checkBodyData(UserEmailNotificationValidator_1.createUserEmailNotificationSchema), UserEmailNotificationService_1.createUserEmailNotification);
router.get("/", checkAuthorization(["CLIENT_ACCESS_TOKEN"]), checkPermissions(["FIND_ANY_USER_EMAIL_NOTIFICATION", "FIND_OWN_USER_EMAIL_NOTIFICATION"]), checkBodyData(UserEmailNotificationValidator_1.findUserEmailNotificationsSchema), showMiddlewareData, UserEmailNotificationService_1.findUserEmailNotifications);
router.get("/:id", checkAuthorization(["CLIENT_ACCESS_TOKEN"]), checkPermissions(["FIND_ANY_USER_EMAIL_NOTIFICATION", "FIND_OWN_USER_EMAIL_NOTIFICATION"]), checkBodyData(UserEmailNotificationValidator_1.findUserEmailNotificationSchema), UserEmailNotificationService_1.findUserEmailNotification);
router.patch("/:id", checkAuthorization(["CLIENT_ACCESS_TOKEN"]), checkPermissions(["UPDATE_ANY_USER_EMAIL_NOTIFICATION", "UPDATE_OWN_USER_EMAIL_NOTIFICATION"]), checkBodyData(UserEmailNotificationValidator_1.updateUserEmailNotificationSchema), UserEmailNotificationService_1.updateUserEmailNotification);
router["delete"]("/:id", checkAuthorization(["CLIENT_ACCESS_TOKEN"]), checkPermissions(["DELETE_ANY_USER_EMAIL_NOTIFICATION", "DELETE_OWN_USER_EMAIL_NOTIFICATION"]), checkBodyData(UserEmailNotificationValidator_1.deleteUserEmailNotificationSchema), UserEmailNotificationService_1.deleteUserEmailNotification);
// router.post("/:id/send", verifyUser, async (req:Request, res:Response, next:NextFunction) => {
//     sendUserEmailNotification(req, res).catch((error) => {
//         next(error);
//     });
// });
module.exports = router;
