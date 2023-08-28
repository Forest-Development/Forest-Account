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
exports.sendNotification = exports.checkClientScopes = exports.checkAuthorizationCodeGrantType = exports.checkClientCredentialsGrantType = exports.checkPasswordGrantType = exports.checkGrantType = exports.checkClientId = void 0;
var HTTPError_1 = require("../types/HTTPError");
var client_1 = require("@prisma/client");
var UserEmailNotificationBuilder_1 = require("../builders/UserEmailNotificationBuilder");
var prisma = new client_1.PrismaClient();
var bcrypt = require("bcrypt");
exports.checkClientId = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var client, error_1;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                if (!req.body.data.clientId) {
                    throw new HTTPError_1.BadRequestError("Client id not found");
                }
                return [4 /*yield*/, prisma.client.findUnique({
                        where: {
                            id: req.body.data.clientId
                        },
                        include: {
                            clientScopes: {
                                include: {
                                    scope: true
                                }
                            },
                            clientAllowedScopes: {
                                include: {
                                    scope: true
                                }
                            }
                        }
                    })];
            case 1:
                client = _a.sent();
                if (!client) {
                    throw new HTTPError_1.NotFoundError("Client not found");
                }
                else if (client.active === false) {
                    throw new HTTPError_1.ForbiddenError("Client already deactivated");
                }
                req.body.middlewareData.client = client;
                return [3 /*break*/, 3];
            case 2:
                error_1 = _a.sent();
                next(error_1);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.checkGrantType = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var error_2;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 9, , 10]);
                if (!!req.body.data.grantType) return [3 /*break*/, 1];
                throw new HTTPError_1.BadRequestError("Grant type not found");
            case 1:
                if (!(req.body.data.grantType === "password")) return [3 /*break*/, 3];
                return [4 /*yield*/, exports.checkPasswordGrantType(req, res, next)];
            case 2:
                _a.sent();
                return [3 /*break*/, 8];
            case 3:
                if (!(req.body.data.grantType === "client_credentials")) return [3 /*break*/, 5];
                return [4 /*yield*/, exports.checkClientCredentialsGrantType(req, res, next)];
            case 4:
                _a.sent();
                return [3 /*break*/, 8];
            case 5:
                if (!(req.body.data.grantType === "authorization_code")) return [3 /*break*/, 7];
                return [4 /*yield*/, exports.checkAuthorizationCodeGrantType(req, res, next)];
            case 6:
                _a.sent();
                return [3 /*break*/, 8];
            case 7: throw new HTTPError_1.BadRequestError("Invalid grant type");
            case 8:
                next();
                return [3 /*break*/, 10];
            case 9:
                error_2 = _a.sent();
                throw error_2;
            case 10: return [2 /*return*/];
        }
    });
}); };
exports.checkPasswordGrantType = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var user, validPassword, error_3;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                if (!req.body.data.email) {
                    throw new HTTPError_1.BadRequestError("Email not found");
                }
                else if (!req.body.data.password) {
                    throw new HTTPError_1.BadRequestError("Password not found");
                }
                return [4 /*yield*/, prisma.user.findUnique({
                        where: {
                            email: req.body.data.email
                        },
                        include: {
                            userPasswords: {
                                where: {
                                    active: true
                                },
                                orderBy: {
                                    createdAt: 'desc'
                                }
                            }
                        }
                    })];
            case 1:
                user = _a.sent();
                if (!user) {
                    throw new HTTPError_1.NotFoundError("User not found");
                }
                if (user.active === false) {
                    throw new HTTPError_1.UnauthorizedError("User already deactivated");
                }
                if (user.userPasswords.length === 0) {
                    throw new HTTPError_1.NotFoundError("No password set");
                }
                return [4 /*yield*/, bcrypt.compare(req.body.data.password, user.userPasswords[0].passwordHash)];
            case 2:
                validPassword = _a.sent();
                if (!validPassword) {
                    throw new HTTPError_1.UnauthorizedError("Wrong password");
                }
                next();
                return [3 /*break*/, 4];
            case 3:
                error_3 = _a.sent();
                next(error_3);
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); };
exports.checkClientCredentialsGrantType = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    return __generator(this, function (_a) {
        try {
            if (!req.body.middlewareData.token) {
                throw new HTTPError_1.BadRequestError("Token not found");
            }
            next();
        }
        catch (error) {
            next(error);
        }
        return [2 /*return*/];
    });
}); };
exports.checkAuthorizationCodeGrantType = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var clientAuthorizationCode, error_4;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                if (!req.body.data.code) {
                    throw new HTTPError_1.BadRequestError("Code not found");
                }
                return [4 /*yield*/, prisma.clientAuthorizationCode.findUnique({
                        where: {
                            code: req.body.data.code
                        },
                        include: {
                            user: true
                        }
                    })];
            case 1:
                clientAuthorizationCode = _a.sent();
                if (!clientAuthorizationCode) {
                    throw new HTTPError_1.NotFoundError("Authorization code not found");
                }
                if (clientAuthorizationCode.clientId !== req.body.middlewareData.client.id) {
                    throw new HTTPError_1.UnauthorizedError("Client not authorized");
                }
                if (clientAuthorizationCode.active === false) {
                    throw new HTTPError_1.UnauthorizedError("Authorization code already used");
                }
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
exports.checkClientScopes = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var clientRequestedScopes, clientScopes_1, clientAllowedScopes_1, clientNotAllowedScopesToAllow_1, createdClientAllowedScopes, findedClientAllowedScopes, clientAllowedScopeNames_1, error_5;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 4, , 5]);
                clientRequestedScopes = req.body.data.scopes;
                clientScopes_1 = [];
                clientAllowedScopes_1 = [];
                clientNotAllowedScopesToAllow_1 = [];
                req.body.middlewareData.client.clientScopes.forEach(function (clientScope) {
                    clientScopes_1.push(clientScope.scope.name);
                });
                req.body.middlewareData.client.clientAllowedScopes.forEach(function (clientAllowedScope) {
                    clientAllowedScopes_1.push(clientAllowedScope.scope.name);
                });
                clientRequestedScopes.forEach(function (clientRequestedScope) {
                    if (clientScopes_1.includes(clientRequestedScope)) {
                        if (!clientAllowedScopes_1.includes(clientRequestedScope)) {
                            clientNotAllowedScopesToAllow_1.push(clientRequestedScope);
                        }
                    }
                    else {
                        throw new HTTPError_1.BadRequestError("Client requested scope not allowed");
                    }
                });
                if (!(clientNotAllowedScopesToAllow_1.length > 0)) return [3 /*break*/, 2];
                return [4 /*yield*/, prisma.clientAllowedScope.createMany({
                        data: clientNotAllowedScopesToAllow_1.map(function (clientNotAllowedScope) {
                            var _a;
                            return {
                                clientId: req.body.middlewareData.client.id,
                                scopeId: (_a = req.body.middlewareData.client.clientScopes.find(function (clientScope) { return clientScope.scope.name === clientNotAllowedScope; })) === null || _a === void 0 ? void 0 : _a.scopeId,
                                userId: req.body.middlewareData.token.userId
                            };
                        })
                    })];
            case 1:
                createdClientAllowedScopes = _a.sent();
                _a.label = 2;
            case 2: return [4 /*yield*/, prisma.clientAllowedScope.findMany({
                    where: {
                        clientId: req.body.middlewareData.client.id
                    },
                    include: {
                        scope: true
                    }
                })];
            case 3:
                findedClientAllowedScopes = _a.sent();
                clientAllowedScopeNames_1 = [];
                findedClientAllowedScopes.forEach(function (findedClientAllowedScope) {
                    clientAllowedScopeNames_1.push(findedClientAllowedScope.scope.name);
                });
                req.body.middlewareData.clientAllowedScopeNames = clientAllowedScopeNames_1;
                return [3 /*break*/, 5];
            case 4:
                error_5 = _a.sent();
                next(error_5);
                return [3 /*break*/, 5];
            case 5: return [2 /*return*/];
        }
    });
}); };
exports.sendNotification = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var user, error_6;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                return [4 /*yield*/, prisma.user.findUnique({
                        where: {
                            id: req.body.middlewareData.token.userId
                        }
                    })];
            case 1:
                user = _a.sent();
                new UserEmailNotificationBuilder_1.UserEmailNotificationBuilder()
                    .withUserId(req.body.middlewareData.token.userId)
                    .withSubject("Client authorized")
                    .withTemplate("ClientAuthorized")
                    .withContext({
                    firstName: user.firstName,
                    clientAllowedScopes: req.body.middlewareData.clientAllowedScopeNames
                })
                    .send();
                return [3 /*break*/, 3];
            case 2:
                error_6 = _a.sent();
                next(error_6);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
