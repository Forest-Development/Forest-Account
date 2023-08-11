import express, { Request, Response, NextFunction, Router } from 'express';
const { checkAuthorization, checkPermissions, checkUserId, checkBodyData, showMiddlewareData } = require("../middlewares/CheckMiddleware");
import { authorizeClient, exchangeClientToken, refreshClientToken, findClientToken, deactivateClientToken } from '../services/ClientAuthorizationService';
const router: Router = express.Router();

router.post("/authorize",
    checkAuthorization(["USER_ACCESS_TOKEN"]),
    checkPermissions([]),
    // checkBodyData(),
    showMiddlewareData,
    authorizeClient
);

router.post("/token",
    checkAuthorization([]),
    checkPermissions([]),
    // checkBodyData(),
    showMiddlewareData,
    exchangeClientToken
);

router.post("/refresh",
    checkAuthorization(["CLIENT_REFRESH_TOKEN"]),
    checkPermissions([]),
    // checkBodyData(), 
    showMiddlewareData,
    refreshClientToken
);

router.post("/introspect",
    checkAuthorization(["CLIENT_ACCESS_TOKEN", "CLIENT_REFRESH_TOKEN"]),
    checkPermissions([]),
    // checkBodyData(), 
    showMiddlewareData,
    findClientToken
);

router.post("/revoke",
    checkAuthorization(["CLIENT_ACCESS_TOKEN", "CLIENT_REFRESH_TOKEN"]),
    checkPermissions([]),
    // checkBodyData(),
    showMiddlewareData,
    deactivateClientToken
);

module.exports = router;