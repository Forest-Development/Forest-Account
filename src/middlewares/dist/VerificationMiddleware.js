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
exports.checkBodyData = exports.checkUserPermissions = exports.checkUserId = exports.checkClientAccessToken = exports.checkUserAccessToken = void 0;
var Response_1 = require("../types/Response");
var jsonwebtoken_1 = require("jsonwebtoken");
var client_1 = require("@prisma/client");
var prisma = new client_1.PrismaClient();
exports.checkUserAccessToken = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var token, userAccessToken, userAccessTokenSecret, decoded, error_1;
    var _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 2, , 3]);
                token = (_a = req.header('Authorization')) === null || _a === void 0 ? void 0 : _a.replace('Bearer ', '');
                if (!token) {
                    throw new Response_1.ResponseError("No token provided", "Provide a valid token", 400);
                }
                return [4 /*yield*/, prisma.userAccessToken.findUnique({
                        where: {
                            token: token
                        }
                    })];
            case 1:
                userAccessToken = _b.sent();
                if (!userAccessToken) {
                    throw new Response_1.ResponseError("Token not found", "Check token", 404);
                }
                if (userAccessToken.expiresAt < new Date()) {
                    throw new Response_1.ResponseError("Token expired", "Check token", 404);
                }
                if (userAccessToken.active === false) {
                    throw new Response_1.ResponseError("Token already deactivated", "Check token", 404);
                }
                userAccessTokenSecret = process.env.USER_ACCESS_TOKEN_SECRET;
                decoded = jsonwebtoken_1["default"].verify(token, userAccessTokenSecret);
                if (!req.body.middlewareData)
                    req.body.middlewareData = {};
                req.body.middlewareData.userAccessToken = decoded;
                console.log("checkUserAccessToken");
                console.log(req.body);
                next();
                return [3 /*break*/, 3];
            case 2:
                error_1 = _b.sent();
                next(error_1);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.checkClientAccessToken = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var token, clientAccessToken, clientAccessTokenSecret, decoded, error_2;
    var _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 2, , 3]);
                token = (_a = req.header('Authorization')) === null || _a === void 0 ? void 0 : _a.replace('Bearer ', '');
                if (!token) {
                    throw new Response_1.ResponseError("No token provided", "Provide a valid token", 400);
                }
                return [4 /*yield*/, prisma.clientAccessToken.findUnique({
                        where: {
                            token: token
                        }
                    })];
            case 1:
                clientAccessToken = _b.sent();
                if (!clientAccessToken) {
                    throw new Response_1.ResponseError("Token not found", "Check token", 404);
                }
                if (clientAccessToken.expiresAt < new Date()) {
                    throw new Response_1.ResponseError("Token expired", "Check token", 404);
                }
                if (clientAccessToken.active === false) {
                    throw new Response_1.ResponseError("Token already deactivated", "Check token", 404);
                }
                clientAccessTokenSecret = process.env.CLIENT_ACCESS_TOKEN_SECRET;
                decoded = jsonwebtoken_1["default"].verify(token, clientAccessTokenSecret);
                if (!req.body.middlewareData)
                    req.body.middlewareData = {};
                req.body.middlewareData.clientAccessToken = decoded;
                console.log("checkClientAccessToken");
                console.log(req.body);
                next();
                return [3 /*break*/, 3];
            case 2:
                error_2 = _b.sent();
                next(error_2);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.checkUserId = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var user, error_3;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 4, , 5]);
                if (!(req.params.uid === "me" || req.params.uid === "self")) return [3 /*break*/, 1];
                if (!req.body.middlewareData)
                    req.body.middlewareData = {};
                req.body.middlewareData.userId = req.body.middlewareData.userAccessToken.userId || req.body.middlewareData.clientAccessToken.userId;
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
                    throw new Response_1.ResponseError("User not found", "Check user ID", 404);
                }
                if (!req.body.middlewareData)
                    req.body.middlewareData = {};
                req.body.middlewareData.userId = user.id;
                _a.label = 3;
            case 3:
                console.log("checkUserId");
                console.log(req.body);
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
exports.checkUserPermissions = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var user, permissions_1, error_4;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                return [4 /*yield*/, prisma.user.findUnique({
                        where: {
                            id: req.body.middlewareData.userAccessToken.userId || req.body.middlewareData.clientAccessToken.userId
                        },
                        include: {
                            userRoles: {
                                include: {
                                    role: {
                                        include: {
                                            rolePermissions: {
                                                include: {
                                                    permission: true
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
                    throw new Response_1.ResponseError("User not found", "Check user ID", 404);
                }
                permissions_1 = [];
                user.userRoles.forEach(function (userRole) {
                    userRole.role.rolePermissions.forEach(function (rolePermission) {
                        permissions_1.push(rolePermission.permission.name);
                    });
                });
                if (!req.body.middlewareData)
                    req.body.middlewareData = {};
                req.body.middlewareData.userPermissions = permissions_1;
                console.log("checkUserPermissions");
                console.log(req.body);
                next();
                return [3 /*break*/, 3];
            case 2:
                error_4 = _a.sent();
                next(error_4);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.checkBodyData = function (schema) {
    return function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
        var _a, error, value, error_5;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    _b.trys.push([0, 2, , 3]);
                    return [4 /*yield*/, schema.validate(req.body.data)];
                case 1:
                    _a = _b.sent(), error = _a.error, value = _a.value;
                    if (!req.body.middlewareData)
                        req.body.middlewareData = {};
                    req.body.middlewareData.bodyValidation = {
                        error: error,
                        value: value
                    };
                    if (error) {
                        throw new Response_1.ResponseError(error.message, "Validation error", 400);
                    }
                    console.log("validateBody");
                    console.log(req.body);
                    next();
                    return [3 /*break*/, 3];
                case 2:
                    error_5 = _b.sent();
                    next(error_5);
                    return [3 /*break*/, 3];
                case 3: return [2 /*return*/];
            }
        });
    }); };
};
