"use strict";
exports.__esModule = true;
var express_1 = require("express");
var _a = require("../middlewares/CheckMiddleware"), checkAuthorization = _a.checkAuthorization, checkPermissions = _a.checkPermissions, checkUserId = _a.checkUserId, checkBodyData = _a.checkBodyData, showMiddlewareData = _a.showMiddlewareData;
var ClientAuthorizationService_1 = require("../services/ClientAuthorizationService");
var router = express_1["default"].Router();
router.post("/authorize", checkAuthorization(["USER_ACCESS_TOKEN"]), checkPermissions([]), 
// checkBodyData(),
showMiddlewareData, ClientAuthorizationService_1.authorizeClient);
router.post("/token", checkAuthorization([]), checkPermissions([]), 
// checkBodyData(),
showMiddlewareData, ClientAuthorizationService_1.exchangeClientToken);
router.post("/refresh", checkAuthorization(["CLIENT_REFRESH_TOKEN"]), checkPermissions([]), 
// checkBodyData(), 
showMiddlewareData, ClientAuthorizationService_1.refreshClientToken);
router.post("/introspect", checkAuthorization(["CLIENT_ACCESS_TOKEN", "CLIENT_REFRESH_TOKEN"]), checkPermissions([]), 
// checkBodyData(), 
showMiddlewareData, ClientAuthorizationService_1.findClientToken);
router.post("/revoke", checkAuthorization(["CLIENT_ACCESS_TOKEN", "CLIENT_REFRESH_TOKEN"]), checkPermissions([]), 
// checkBodyData(),
showMiddlewareData, ClientAuthorizationService_1.deactivateClientToken);
module.exports = router;
