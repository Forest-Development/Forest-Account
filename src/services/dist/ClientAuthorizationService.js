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
exports.deactivateClientToken = exports.findClientToken = exports.refreshClientToken = exports.authorizeClientCodeGrantType = exports.authorizeClientCredentialsGrantType = exports.authorizeClientPasswordGrantType = void 0;
var client_1 = require("@prisma/client");
var HTTPResponse_1 = require("../types/HTTPResponse");
var HTTPSuccess_1 = require("../types/HTTPSuccess");
var HTTPError_1 = require("../types/HTTPError");
var jsonwebtoken_1 = require("jsonwebtoken");
var UserEmailNotificationBuilder_1 = require("../builders/UserEmailNotificationBuilder");
var prisma = new client_1.PrismaClient();
var bcrypt = require("bcrypt");
exports.authorizeClientPasswordGrantType = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var client, user, validPassword, tokenSecret, responseBody, clientRefreshToken, clientAccessToken, responseBodyResult, clientRequestedScopes, clientScopes_1, clientAllowedScopes_1, clientNotAllowedScopesToAllow_1, createdClientAllowedScopes, findedClientAllowedScopes, clientAllowedScopeNames_1, error_1;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 9, , 10]);
                //check grant type
                if (!req.body.data.grantType) {
                    throw new HTTPError_1.BadRequestError("Grant type not found");
                }
                else if (req.body.data.grantType !== "password") {
                    throw new HTTPError_1.BadRequestError("Invalid grant type");
                }
                //check response type
                if (!req.body.data.responseType) {
                    throw new HTTPError_1.BadRequestError("Response type not found");
                }
                else if (req.body.data.responseType !== "token") {
                    throw new HTTPError_1.BadRequestError("Invalid response type");
                }
                //check client
                if (!req.body.data.clientId) {
                    throw new HTTPError_1.BadRequestError("Client id not found");
                }
                return [4 /*yield*/, prisma.client.findUnique({
                        where: {
                            id: req.body.data.clientId,
                            secret: req.body.data.clientSecret
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
                //check user
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
            case 2:
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
            case 3:
                validPassword = _a.sent();
                if (!validPassword) {
                    throw new HTTPError_1.UnauthorizedError("Wrong password");
                }
                tokenSecret = process.env.TOKEN_SECRET;
                responseBody = void 0;
                if (!tokenSecret) {
                    throw new HTTPError_1.InternalServerError("Token secret not found");
                }
                return [4 /*yield*/, prisma.clientRefreshToken.create({
                        data: {
                            userId: user.id,
                            clientId: client.id,
                            token: jsonwebtoken_1["default"].sign({
                                userId: user.id,
                                clientId: client.id,
                                tokenType: "CLIENT_REFRESH_TOKEN"
                            }, tokenSecret, { expiresIn: '7d' }),
                            expiresAt: new Date(Date.now() + 604800000)
                        }
                    })];
            case 4:
                clientRefreshToken = _a.sent();
                return [4 /*yield*/, prisma.clientAccessToken.create({
                        data: {
                            userId: user.id,
                            clientId: client.id,
                            token: jsonwebtoken_1["default"].sign({
                                userId: user.id,
                                clientId: client.id,
                                tokenType: "CLIENT_ACCESS_TOKEN"
                            }, tokenSecret, { expiresIn: '1d' }),
                            expiresAt: new Date(Date.now() + 86400000),
                            clientRefreshTokenId: clientRefreshToken.id
                        }
                    })];
            case 5:
                clientAccessToken = _a.sent();
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_CREATED, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody({ clientRefreshToken: clientRefreshToken, clientAccessToken: clientAccessToken }, responseBodyResult);
                if (!req.body.data.scopes) return [3 /*break*/, 7];
                clientRequestedScopes = req.body.data.scopes;
                clientScopes_1 = [];
                clientAllowedScopes_1 = [];
                clientNotAllowedScopesToAllow_1 = [];
                client.clientScopes.forEach(function (clientScope) {
                    clientScopes_1.push(clientScope.scope.name);
                });
                client.clientAllowedScopes.forEach(function (clientAllowedScope) {
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
                if (!(clientNotAllowedScopesToAllow_1.length > 0)) return [3 /*break*/, 7];
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
            case 6:
                createdClientAllowedScopes = _a.sent();
                _a.label = 7;
            case 7: return [4 /*yield*/, prisma.clientAllowedScope.findMany({
                    where: {
                        clientId: client.id
                    },
                    include: {
                        scope: true
                    }
                })];
            case 8:
                findedClientAllowedScopes = _a.sent();
                clientAllowedScopeNames_1 = [];
                findedClientAllowedScopes.forEach(function (findedClientAllowedScope) {
                    clientAllowedScopeNames_1.push(findedClientAllowedScope.scope.name);
                });
                new UserEmailNotificationBuilder_1.UserEmailNotificationBuilder()
                    .withUserId(user.id)
                    .withSubject("Client authorized")
                    .withTemplate("ClientAuthorized")
                    .withContext({
                    firstName: user.firstName,
                    clientAllowedScopes: clientAllowedScopeNames_1
                })
                    .send();
                //send response
                res.status(201).json(responseBody);
                return [3 /*break*/, 10];
            case 9:
                error_1 = _a.sent();
                next(error_1);
                return [3 /*break*/, 10];
            case 10: return [2 /*return*/];
        }
    });
}); };
exports.authorizeClientCredentialsGrantType = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var client_2, tokenSecret, responseBody, clientAuthorizationCode, responseBodyResult, clientRefreshToken, clientAccessToken, responseBodyResult, clientRequestedScopes, clientScopes_2, clientAllowedScopes_2, clientNotAllowedScopesToAllow_2, createdClientAllowedScopes, user, findedClientAllowedScopes, clientAllowedScopeNames_2, error_2;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 12, , 13]);
                //check grant type
                if (!req.body.data.grantType) {
                    throw new HTTPError_1.BadRequestError("Grant type not found");
                }
                else if (req.body.data.grantType !== "client_credentials") {
                    throw new HTTPError_1.BadRequestError("Invalid grant type");
                }
                //check response type
                if (!req.body.data.responseType) {
                    throw new HTTPError_1.BadRequestError("Response type not found");
                }
                else if (req.body.data.responseType !== "token" && req.body.data.responseType !== "code") {
                    throw new HTTPError_1.BadRequestError("Invalid response type");
                }
                //check client
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
                client_2 = _a.sent();
                if (!client_2) {
                    throw new HTTPError_1.NotFoundError("Client not found");
                }
                else if (client_2.active === false) {
                    throw new HTTPError_1.ForbiddenError("Client already deactivated");
                }
                tokenSecret = process.env.TOKEN_SECRET;
                responseBody = void 0;
                if (!tokenSecret) {
                    throw new HTTPError_1.InternalServerError("Token secret not found");
                }
                if (!(req.body.data.responseType === "code")) return [3 /*break*/, 3];
                return [4 /*yield*/, prisma.clientAuthorizationCode.create({
                        data: {
                            userId: req.body.middlewareData.token.userId,
                            clientId: client_2.id,
                            code: jsonwebtoken_1["default"].sign({ userId: req.body.middlewareData.token.userId, clientId: client_2.id, tokenType: "CLIENT_AUTHORIZATION_CODE" }, tokenSecret, { expiresIn: '1m' }),
                            expiresAt: new Date(Date.now() + 60000)
                        }
                    })];
            case 2:
                clientAuthorizationCode = _a.sent();
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_CREATED, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody(clientAuthorizationCode, responseBodyResult);
                return [3 /*break*/, 7];
            case 3:
                if (!(req.body.data.responseType === "token")) return [3 /*break*/, 6];
                if (!req.body.data.clientSecret) {
                    throw new HTTPError_1.BadRequestError("Client secret not found");
                }
                else if (req.body.data.clientSecret !== client_2.secret) {
                    throw new HTTPError_1.UnauthorizedError("Invalid client secret");
                }
                return [4 /*yield*/, prisma.clientRefreshToken.create({
                        data: {
                            userId: req.body.middlewareData.token.userId,
                            clientId: client_2.id,
                            token: jsonwebtoken_1["default"].sign({
                                userId: req.body.middlewareData.token.userId,
                                clientId: client_2.id,
                                tokenType: "CLIENT_REFRESH_TOKEN"
                            }, tokenSecret, { expiresIn: '7d' }),
                            expiresAt: new Date(Date.now() + 604800000)
                        }
                    })];
            case 4:
                clientRefreshToken = _a.sent();
                return [4 /*yield*/, prisma.clientAccessToken.create({
                        data: {
                            userId: req.body.middlewareData.token.userId,
                            clientId: client_2.id,
                            token: jsonwebtoken_1["default"].sign({
                                userId: req.body.middlewareData.token.userId,
                                clientId: client_2.id,
                                tokenType: "CLIENT_ACCESS_TOKEN"
                            }, tokenSecret, { expiresIn: '1d' }),
                            expiresAt: new Date(Date.now() + 86400000),
                            clientRefreshTokenId: clientRefreshToken.id
                        }
                    })];
            case 5:
                clientAccessToken = _a.sent();
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_CREATED, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody({ clientRefreshToken: clientRefreshToken, clientAccessToken: clientAccessToken }, responseBodyResult);
                return [3 /*break*/, 7];
            case 6: throw new HTTPError_1.BadRequestError("Invalid response type");
            case 7:
                if (!req.body.data.scopes) return [3 /*break*/, 9];
                clientRequestedScopes = req.body.data.scopes;
                clientScopes_2 = [];
                clientAllowedScopes_2 = [];
                clientNotAllowedScopesToAllow_2 = [];
                client_2.clientScopes.forEach(function (clientScope) {
                    clientScopes_2.push(clientScope.scope.name);
                });
                client_2.clientAllowedScopes.forEach(function (clientAllowedScope) {
                    clientAllowedScopes_2.push(clientAllowedScope.scope.name);
                });
                clientRequestedScopes.forEach(function (clientRequestedScope) {
                    if (clientScopes_2.includes(clientRequestedScope)) {
                        if (!clientAllowedScopes_2.includes(clientRequestedScope)) {
                            clientNotAllowedScopesToAllow_2.push(clientRequestedScope);
                        }
                    }
                    else {
                        throw new HTTPError_1.BadRequestError("Client requested scope not allowed");
                    }
                });
                if (!(clientNotAllowedScopesToAllow_2.length > 0)) return [3 /*break*/, 9];
                return [4 /*yield*/, prisma.clientAllowedScope.createMany({
                        data: clientNotAllowedScopesToAllow_2.map(function (clientNotAllowedScope) {
                            var _a;
                            return {
                                clientId: client_2.id,
                                scopeId: (_a = client_2.clientScopes.find(function (clientScope) { return clientScope.scope.name === clientNotAllowedScope; })) === null || _a === void 0 ? void 0 : _a.scopeId,
                                userId: req.body.middlewareData.token.userId
                            };
                        })
                    })];
            case 8:
                createdClientAllowedScopes = _a.sent();
                _a.label = 9;
            case 9: return [4 /*yield*/, prisma.user.findUnique({
                    where: {
                        id: req.body.middlewareData.token.userId
                    }
                })];
            case 10:
                user = _a.sent();
                return [4 /*yield*/, prisma.clientAllowedScope.findMany({
                        where: {
                            clientId: client_2.id
                        },
                        include: {
                            scope: true
                        }
                    })];
            case 11:
                findedClientAllowedScopes = _a.sent();
                clientAllowedScopeNames_2 = [];
                findedClientAllowedScopes.forEach(function (findedClientAllowedScope) {
                    clientAllowedScopeNames_2.push(findedClientAllowedScope.scope.name);
                });
                new UserEmailNotificationBuilder_1.UserEmailNotificationBuilder()
                    .withUserId(req.body.middlewareData.token.userId)
                    .withSubject("Client authorized")
                    .withTemplate("ClientAuthorized")
                    .withContext({
                    firstName: user.firstName,
                    clientAllowedScopes: clientAllowedScopeNames_2
                })
                    .send();
                //send response
                res.status(201).json(responseBody);
                return [3 /*break*/, 13];
            case 12:
                error_2 = _a.sent();
                next(error_2);
                return [3 /*break*/, 13];
            case 13: return [2 /*return*/];
        }
    });
}); };
exports.authorizeClientCodeGrantType = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var client, clientAuthorizationCode, tokenSecret, clientRefreshToken, clientAccessToken, responseBodyResult, responseBody, error_3;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 6, , 7]);
                //check grant type
                if (!req.body.data.grantType) {
                    throw new HTTPError_1.BadRequestError("Grant type not found");
                }
                else if (req.body.data.grantType !== "authorization_code") {
                    throw new HTTPError_1.BadRequestError("Invalid grant type");
                }
                //check response type
                if (!req.body.data.responseType) {
                    throw new HTTPError_1.BadRequestError("Response type not found");
                }
                else if (req.body.data.responseType !== "token") {
                    throw new HTTPError_1.BadRequestError("Invalid response type");
                }
                return [4 /*yield*/, prisma.client.findUnique({
                        where: {
                            id: req.body.data.clientId,
                            secret: req.body.data.clientSecret
                        }
                    })];
            case 1:
                client = _a.sent();
                if (!client) {
                    throw new HTTPError_1.NotFoundError("Client not found");
                }
                if (client.active === false) {
                    throw new HTTPError_1.ForbiddenError("Client already deactivated");
                }
                return [4 /*yield*/, prisma.clientAuthorizationCode.findUnique({
                        where: {
                            code: req.body.data.code
                        },
                        include: {
                            user: true
                        }
                    })];
            case 2:
                clientAuthorizationCode = _a.sent();
                if (!clientAuthorizationCode) {
                    throw new HTTPError_1.NotFoundError("Authorization code not found");
                }
                if (clientAuthorizationCode.clientId !== client.id) {
                    throw new HTTPError_1.UnauthorizedError("Client not authorized");
                }
                if (clientAuthorizationCode.active === false) {
                    throw new HTTPError_1.UnauthorizedError("Authorization code already used");
                }
                tokenSecret = process.env.TOKEN_SECRET;
                return [4 /*yield*/, prisma.clientRefreshToken.create({
                        data: {
                            userId: clientAuthorizationCode.userId,
                            clientId: client.id,
                            token: jsonwebtoken_1["default"].sign({
                                userId: clientAuthorizationCode.userId,
                                clientId: client.id,
                                tokenType: "CLIENT_REFRESH_TOKEN"
                            }, tokenSecret, { expiresIn: '7d' }),
                            expiresAt: new Date(Date.now() + 604800000),
                            clientAuthorizationCodeId: clientAuthorizationCode.id
                        }
                    })];
            case 3:
                clientRefreshToken = _a.sent();
                return [4 /*yield*/, prisma.clientAccessToken.create({
                        data: {
                            userId: clientAuthorizationCode.userId,
                            clientId: client.id,
                            token: jsonwebtoken_1["default"].sign({
                                userId: clientAuthorizationCode.userId,
                                clientId: client.id,
                                tokenType: "CLIENT_ACCESS_TOKEN"
                            }, tokenSecret, { expiresIn: '1d' }),
                            expiresAt: new Date(Date.now() + 86400000),
                            clientRefreshTokenId: clientRefreshToken.id,
                            clientAuthorizationCodeId: clientAuthorizationCode.id
                        }
                    })];
            case 4:
                clientAccessToken = _a.sent();
                return [4 /*yield*/, prisma.clientAuthorizationCode.update({
                        where: {
                            id: clientAuthorizationCode.id
                        },
                        data: {
                            active: false
                        }
                    })];
            case 5:
                _a.sent();
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_CREATED, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody({ clientRefreshToken: clientRefreshToken, clientAccessToken: clientAccessToken }, responseBodyResult);
                //send response
                res.status(201).json(responseBody);
                return [3 /*break*/, 7];
            case 6:
                error_3 = _a.sent();
                next(error_3);
                return [3 /*break*/, 7];
            case 7: return [2 /*return*/];
        }
    });
}); };
exports.refreshClientToken = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var record, tokenSecret, responseBodyResult, responseBody, error_4;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 4, , 5]);
                record = void 0;
                tokenSecret = process.env.TOKEN_SECRET;
                if (!(req.body.middlewareData.token.tokenType === "CLIENT_REFRESH_TOKEN")) return [3 /*break*/, 2];
                return [4 /*yield*/, prisma.clientAccessToken.create({
                        data: {
                            userId: req.body.middlewareData.token.userId,
                            clientId: req.body.middlewareData.token.clientId,
                            token: jsonwebtoken_1["default"].sign({
                                userId: req.body.middlewareData.token.userId,
                                clientId: req.body.middlewareData.token.clientId,
                                tokenType: "CLIENT_ACCESS_TOKEN"
                            }, tokenSecret, { expiresIn: '1d' }),
                            expiresAt: new Date(Date.now() + 600000),
                            clientRefreshTokenId: req.body.middlewareData.token.id,
                            clientAuthorizationCodeId: req.body.middlewareData.token.clientAuthorizationCodeId
                        }
                    })];
            case 1:
                record = _a.sent();
                return [3 /*break*/, 3];
            case 2: throw new HTTPError_1.BadRequestError("Invalid token type");
            case 3:
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_CREATED, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody(record, responseBodyResult);
                res.status(201).json(responseBody);
                return [3 /*break*/, 5];
            case 4:
                error_4 = _a.sent();
                next(error_4);
                return [3 /*break*/, 5];
            case 5: return [2 /*return*/];
        }
    });
}); };
exports.findClientToken = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var record, responseBodyResult, responseBody, error_5;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 6, , 7]);
                record = void 0;
                if (!(req.body.middlewareData.token.tokenType === "CLIENT_ACCESS_TOKEN")) return [3 /*break*/, 2];
                return [4 /*yield*/, prisma.clientAccessToken.findUnique({
                        where: {
                            token: req.body.middlewareData.token.token
                        }
                    })];
            case 1:
                record = _a.sent();
                return [3 /*break*/, 5];
            case 2:
                if (!(req.body.middlewareData.token.tokenType === "CLIENT_REFRESH_TOKEN")) return [3 /*break*/, 4];
                return [4 /*yield*/, prisma.clientRefreshToken.findUnique({
                        where: {
                            token: req.body.middlewareData.token.token
                        }
                    })];
            case 3:
                record = _a.sent();
                return [3 /*break*/, 5];
            case 4: throw new HTTPError_1.BadRequestError("Invalid token type");
            case 5:
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_FOUND, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody(record, responseBodyResult);
                res.status(201).json(responseBody);
                return [3 /*break*/, 7];
            case 6:
                error_5 = _a.sent();
                next(error_5);
                return [3 /*break*/, 7];
            case 7: return [2 /*return*/];
        }
    });
}); };
exports.deactivateClientToken = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var record, responseBodyResult, responseBody, error_6;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 6, , 7]);
                record = void 0;
                if (!(req.body.middlewareData.token.tokenType === "CLIENT_ACCESS_TOKEN")) return [3 /*break*/, 2];
                return [4 /*yield*/, prisma.clientAccessToken.update({
                        where: { id: req.body.middlewareData.token.id },
                        data: { active: false }
                    })];
            case 1:
                record = _a.sent();
                return [3 /*break*/, 5];
            case 2:
                if (!(req.body.middlewareData.token.tokenType === "CLIENT_REFRESH_TOKEN")) return [3 /*break*/, 4];
                return [4 /*yield*/, prisma.clientRefreshToken.update({
                        where: { id: req.body.middlewareData.token.id },
                        data: { active: false }
                    })];
            case 3:
                record = _a.sent();
                return [3 /*break*/, 5];
            case 4: throw new HTTPError_1.BadRequestError("Invalid token type");
            case 5:
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_DEACTIVATED, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody(record, responseBodyResult);
                res.status(201).json(responseBody);
                return [3 /*break*/, 7];
            case 6:
                error_6 = _a.sent();
                next(error_6);
                return [3 /*break*/, 7];
            case 7: return [2 /*return*/];
        }
    });
}); };
