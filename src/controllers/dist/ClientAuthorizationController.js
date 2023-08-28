"use strict";
exports.__esModule = true;
var express_1 = require("express");
var _a = require("../middlewares/CheckMiddleware"), checkAuthorization = _a.checkAuthorization, checkPermissions = _a.checkPermissions, checkUserId = _a.checkUserId, checkBodyData = _a.checkBodyData, showMiddlewareData = _a.showMiddlewareData;
var ClientAuthorizationService_1 = require("../services/ClientAuthorizationService");
var router = express_1["default"].Router();
var passwordRouter = express_1["default"].Router();
passwordRouter.use(ClientAuthorizationService_1.authorizeClientPasswordGrantType);
var clientCredentialsRouter = express_1["default"].Router();
clientCredentialsRouter.use(checkAuthorization(["CLIENT_ACCESS_TOKEN"]), checkPermissions([]), ClientAuthorizationService_1.authorizeClientCredentialsGrantType);
var codeRouter = express_1["default"].Router();
codeRouter.use(ClientAuthorizationService_1.authorizeClientCodeGrantType);
router.post("/authorize", function (req, res, next) {
    if (req.body.data.grantType === "password") {
        passwordRouter(req, res, next);
    }
    else if (req.body.data.grantType === "client_credentials") {
        clientCredentialsRouter(req, res, next);
    }
    else if (req.body.data.grantType === "authorization_code") {
        codeRouter(req, res, next);
    }
});
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
