"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.showMiddlewareData = exports.checkBodyData = exports.checkUserId = exports.checkFindPermissions = exports.checkPermissions = exports.checkUserAgent = exports.checkAuthorization = void 0;
var HTTPError_1 = require("../types/HTTPError");
var jsonwebtoken_1 = require("jsonwebtoken");
var client_1 = require("@prisma/client");
var prisma = new client_1.PrismaClient();
exports.checkAuthorization = function (requiredTokens) {
    return function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
        var headerToken, tokenSecret, decoded, tokenType, token, error_1;
        var _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    _b.trys.push([0, 9, , 10]);
                    headerToken = (_a = req.header('Authorization')) === null || _a === void 0 ? void 0 : _a.replace('Bearer ', '');
                    if (!headerToken) {
                        throw new HTTPError_1.UnauthorizedError("No token provided");
                    }
                    tokenSecret = process.env.TOKEN_SECRET;
                    if (!tokenSecret) {
                        throw new HTTPError_1.BadRequestError("No token secret provided");
                    }
                    decoded = jsonwebtoken_1["default"].verify(headerToken, tokenSecret);
                    if (!decoded) {
                        throw new HTTPError_1.UnauthorizedError("Invalid token");
                    }
                    if (requiredTokens.length > 0 && (!decoded.tokenType || !requiredTokens.includes(decoded.tokenType))) {
                        throw new HTTPError_1.UnauthorizedError("Invalid token type");
                    }
                    tokenType = decoded.tokenType;
                    token = void 0;
                    if (!(tokenType === "USER_ACCESS_TOKEN")) return [3 /*break*/, 2];
                    return [4 /*yield*/, prisma.userAccessToken.findUnique({
                            where: {
                                token: headerToken
                            },
                            include: {
                                user: true
                            }
                        })];
                case 1:
                    token = _b.sent();
                    return [3 /*break*/, 8];
                case 2:
                    if (!(tokenType === "USER_REFRESH_TOKEN")) return [3 /*break*/, 4];
                    return [4 /*yield*/, prisma.userRefreshToken.findUnique({
                            where: {
                                token: headerToken
                            },
                            include: {
                                user: true
                            }
                        })];
                case 3:
                    token = _b.sent();
                    return [3 /*break*/, 8];
                case 4:
                    if (!(tokenType === "CLIENT_ACCESS_TOKEN")) return [3 /*break*/, 6];
                    return [4 /*yield*/, prisma.clientAccessToken.findUnique({
                            where: {
                                token: headerToken
                            },
                            include: {
                                user: true,
                                client: true
                            }
                        })];
                case 5:
                    token = _b.sent();
                    return [3 /*break*/, 8];
                case 6:
                    if (!(tokenType === "CLIENT_REFRESH_TOKEN")) return [3 /*break*/, 8];
                    return [4 /*yield*/, prisma.clientRefreshToken.findUnique({
                            where: {
                                token: headerToken
                            },
                            include: {
                                user: true,
                                client: true
                            }
                        })];
                case 7:
                    token = _b.sent();
                    _b.label = 8;
                case 8:
                    if (!token) {
                        throw new HTTPError_1.NotFoundError("Token not found");
                    }
                    if (token.expiresAt < new Date()) {
                        throw new HTTPError_1.UnauthorizedError("Token expired");
                    }
                    if (token.active === false) {
                        throw new HTTPError_1.UnauthorizedError("Token deactivated");
                    }
                    if (!req.body.middlewareData)
                        req.body.middlewareData = {};
                    token.tokenType = tokenType;
                    req.body.middlewareData.token = token;
                    next();
                    return [3 /*break*/, 10];
                case 9:
                    error_1 = _b.sent();
                    if (requiredTokens.length > 0) {
                        next(error_1);
                    }
                    else {
                        next();
                    }
                    return [3 /*break*/, 10];
                case 10: return [2 /*return*/];
            }
        });
    }); };
};
exports.checkUserAgent = function () {
    return function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
        var userAgent;
        return __generator(this, function (_a) {
            try {
                userAgent = req.header('User-Agent');
            }
            catch (error) {
                next(error);
            }
            return [2 /*return*/];
        });
    }); };
};
exports.checkPermissions = function (requiredPermissions) {
    return function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
        var includeUserPermissions, userPermissions_1, includeClientAllowedPermissions, clientAllowedPermissions_1, finalPermissions_1, compatiblePermissions, user, client, permissionsConditions, hasAnyPermission_1, hasOwnPermission_1, error_2;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 5, , 6]);
                    if (!req.body.middlewareData.token) {
                        throw new HTTPError_1.UnauthorizedError("No access token provided");
                    }
                    includeUserPermissions = false;
                    userPermissions_1 = [];
                    includeClientAllowedPermissions = false;
                    clientAllowedPermissions_1 = [];
                    finalPermissions_1 = [];
                    compatiblePermissions = [];
                    if (!req.body.middlewareData.token.userId) return [3 /*break*/, 2];
                    return [4 /*yield*/, prisma.user.findUnique({
                            where: {
                                id: req.body.middlewareData.token.userId
                            },
                            include: {
                                userRoles: {
                                    where: {
                                        active: true
                                    },
                                    include: {
                                        role: {
                                            include: {
                                                rolePermissions: {
                                                    where: {
                                                        active: true
                                                    },
                                                    include: {
                                                        permission: {
                                                            include: {
                                                                childPermissions: {
                                                                    where: {
                                                                        active: true
                                                                    },
                                                                    include: {
                                                                        childPermissions: true
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        })];
                case 1:
                    user = _a.sent();
                    if (!user) {
                        throw new HTTPError_1.NotFoundError("User not found");
                    }
                    user.userRoles.forEach(function (userRole) {
                        if (userRole.role.active === false)
                            return;
                        userRole.role.rolePermissions.forEach(function (rolePermission) {
                            if (rolePermission.permission.active === false)
                                return;
                            if (!userPermissions_1.includes(rolePermission.permission.code)) {
                                userPermissions_1.push(rolePermission.permission.code);
                            }
                            rolePermission.permission.childPermissions.forEach(function (childPermission) {
                                if (childPermission.active === false)
                                    return;
                                if (!userPermissions_1.includes(childPermission.code)) {
                                    userPermissions_1.push(childPermission.code);
                                }
                                childPermission.childPermissions.forEach(function (childPermission) {
                                    if (childPermission.active === false)
                                        return;
                                    if (!userPermissions_1.includes(childPermission.code)) {
                                        userPermissions_1.push(childPermission.code);
                                    }
                                });
                            });
                        });
                    });
                    includeUserPermissions = true;
                    _a.label = 2;
                case 2:
                    if (!req.body.middlewareData.token.clientId) return [3 /*break*/, 4];
                    return [4 /*yield*/, prisma.client.findUnique({
                            where: {
                                id: req.body.middlewareData.token.clientId
                            },
                            include: {
                                clientAllowedScopes: {
                                    where: {
                                        active: true,
                                        userId: req.body.middlewareData.token.userId
                                    },
                                    include: {
                                        scope: {
                                            include: {
                                                scopePermissions: {
                                                    where: {
                                                        active: true
                                                    },
                                                    include: {
                                                        permission: {
                                                            include: {
                                                                childPermissions: {
                                                                    where: {
                                                                        active: true
                                                                    },
                                                                    include: {
                                                                        childPermissions: true
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        })];
                case 3:
                    client = _a.sent();
                    if (!client) {
                        throw new HTTPError_1.NotFoundError("Client not found");
                    }
                    client.clientAllowedScopes.forEach(function (clientScope) {
                        clientScope.scope.scopePermissions.forEach(function (scopePermission) {
                            if (!clientAllowedPermissions_1.includes(scopePermission.permission.code)) {
                                clientAllowedPermissions_1.push(scopePermission.permission.code);
                            }
                            scopePermission.permission.childPermissions.forEach(function (childPermission) {
                                if (!clientAllowedPermissions_1.includes(childPermission.code)) {
                                    clientAllowedPermissions_1.push(childPermission.code);
                                }
                                childPermission.childPermissions.forEach(function (childPermission) {
                                    if (!clientAllowedPermissions_1.includes(childPermission.code)) {
                                        clientAllowedPermissions_1.push(childPermission.code);
                                    }
                                });
                            });
                        });
                    });
                    includeClientAllowedPermissions = true;
                    _a.label = 4;
                case 4:
                    if (includeUserPermissions && includeClientAllowedPermissions) {
                        finalPermissions_1 = userPermissions_1.filter(function (value) { return clientAllowedPermissions_1.includes(value); });
                    }
                    else if (includeUserPermissions) {
                        finalPermissions_1 = userPermissions_1;
                    }
                    else if (includeClientAllowedPermissions) {
                        finalPermissions_1 = clientAllowedPermissions_1;
                    }
                    if (requiredPermissions.length > 0) {
                        compatiblePermissions = requiredPermissions.filter(function (value) { return finalPermissions_1.includes(value); });
                    }
                    if (compatiblePermissions.length === 0) {
                        throw new HTTPError_1.ForbiddenError();
                    }
                    if (!req.body.middlewareData)
                        req.body.middlewareData = {};
                    req.body.middlewareData.permissions = compatiblePermissions;
                    permissionsConditions = {};
                    hasAnyPermission_1 = false;
                    hasOwnPermission_1 = false;
                    compatiblePermissions.forEach(function (permission) {
                        if (permission.includes("ANY"))
                            hasAnyPermission_1 = true;
                        if (permission.includes("OWN"))
                            hasOwnPermission_1 = true;
                    });
                    if (!hasAnyPermission_1 && hasOwnPermission_1) {
                        permissionsConditions = {
                            userId: req.body.middlewareData.token.userId
                        };
                        req.body.middlewareData.permissionsConditions = permissionsConditions;
                    }
                    next();
                    return [3 /*break*/, 6];
                case 5:
                    error_2 = _a.sent();
                    if (requiredPermissions.length > 0) {
                        next(error_2);
                    }
                    else {
                        next();
                    }
                    return [3 /*break*/, 6];
                case 6: return [2 /*return*/];
            }
        });
    }); };
};
exports.checkFindPermissions = function () {
    return function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
        var permissionsConditions_1;
        return __generator(this, function (_a) {
            try {
                permissionsConditions_1 = {};
                req.body.middlewareData.permissions.forEach(function (permission) {
                    if (permission.includes("ANY"))
                        next();
                    if (permission.includes("OWN")) {
                        permissionsConditions_1 = {
                            userId: req.body.middlewareData.token.userId
                        };
                    }
                });
                if (!req.body.middlewareData)
                    req.body.middlewareData = {};
                req.body.middlewareData.permissionsConditions = permissionsConditions_1;
                next();
            }
            catch (error) {
                next(error);
            }
            return [2 /*return*/];
        });
    }); };
};
exports.checkUserId = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var user, error_3;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 4, , 5]);
                if (!(req.params.uid === "me" || req.params.uid === "self")) return [3 /*break*/, 1];
                if (!req.body.middlewareData.token) {
                    throw new HTTPError_1.BadRequestError("No token provided");
                }
                if (!req.body.middlewareData)
                    req.body.middlewareData = {};
                req.body.middlewareData.userId = req.body.middlewareData.token.userId;
                return [3 /*break*/, 3];
            case 1: return [4 /*yield*/, prisma.user.findFirst({
                    where: {
                        OR: [
                            {
                                id: req.params.uid
                            },
                            {
                                nickname: req.params.uid
                            },
                            {
                                email: req.params.uid
                            },
                        ]
                    }
                })];
            case 2:
                user = _a.sent();
                if (!user) {
                    throw new HTTPError_1.NotFoundError("User not found");
                }
                if (!req.body.middlewareData)
                    req.body.middlewareData = {};
                req.body.middlewareData.userId = user.id;
                _a.label = 3;
            case 3:
                next();
                return [3 /*break*/, 5];
            case 4:
                error_3 = _a.sent();
                next(error_3);
                return [3 /*break*/, 5];
            case 5: return [2 /*return*/];
        }
    });
}); };
exports.checkBodyData = function (schema) {
    return function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
        var _a, error, value, error_4;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    _b.trys.push([0, 2, , 3]);
                    return [4 /*yield*/, schema.validate(req.body.data)];
                case 1:
                    _a = _b.sent(), error = _a.error, value = _a.value;
                    if (!req.body.middlewareData)
                        req.body.middlewareData = {};
                    req.body.middlewareData.bodyData = {
                        error: error,
                        value: value
                    };
                    if (error) {
                        throw new HTTPError_1.BadRequestError(error.message);
                    }
                    next();
                    return [3 /*break*/, 3];
                case 2:
                    error_4 = _b.sent();
                    next(error_4);
                    return [3 /*break*/, 3];
                case 3: return [2 /*return*/];
            }
        });
    }); };
};
exports.showMiddlewareData = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    return __generator(this, function (_a) {
        try {
            console.log(req.body.middlewareData);
            next();
        }
        catch (error) {
            next(error);
        }
        return [2 /*return*/];
    });
}); };
