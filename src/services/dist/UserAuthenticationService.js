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
exports.deactivateUserToken = exports.findUserToken = exports.refreshUserToken = exports.createUserToken = void 0;
var client_1 = require("@prisma/client");
var HTTPResponse_1 = require("../types/HTTPResponse");
var HTTPSuccess_1 = require("../types/HTTPSuccess");
var HTTPError_1 = require("../types/HTTPError");
var jsonwebtoken_1 = require("jsonwebtoken");
var UserEmailNotificationBuilder_1 = require("../builders/UserEmailNotificationBuilder");
var bcrypt = require("bcrypt");
var prisma = new client_1.PrismaClient();
exports.createUserToken = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var user, validPassword, tokenSecret, userRefreshToken, userAccessToken, responseBodyResult, responseBody, error_1;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 5, , 6]);
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
                tokenSecret = process.env.TOKEN_SECRET;
                return [4 /*yield*/, prisma.userRefreshToken.create({
                        data: {
                            userId: user.id,
                            token: jsonwebtoken_1["default"].sign({ userId: user.id, tokenType: "USER_REFRESH_TOKEN" }, tokenSecret, { expiresIn: '7d' }),
                            expiresAt: new Date(Date.now() + 604800000)
                        }
                    })];
            case 3:
                userRefreshToken = _a.sent();
                return [4 /*yield*/, prisma.userAccessToken.create({
                        data: {
                            userId: user.id,
                            token: jsonwebtoken_1["default"].sign({ userId: user.id, tokenType: "USER_ACCESS_TOKEN" }, tokenSecret, { expiresIn: '1d' }),
                            expiresAt: new Date(Date.now() + 86400000),
                            userRefreshTokenId: userRefreshToken.id
                        }
                    })];
            case 4:
                userAccessToken = _a.sent();
                new UserEmailNotificationBuilder_1.UserEmailNotificationBuilder()
                    .withUserId(user.id)
                    .withSubject("User signed in")
                    .withTemplate("UserAuthenticated")
                    .withContext({
                    firstName: user.firstName
                })
                    .save();
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_CREATED, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody({ userRefreshToken: userRefreshToken, userAccessToken: userAccessToken }, responseBodyResult);
                res.status(200).json(responseBody);
                return [3 /*break*/, 6];
            case 5:
                error_1 = _a.sent();
                next(error_1);
                return [3 /*break*/, 6];
            case 6: return [2 /*return*/];
        }
    });
}); };
exports.refreshUserToken = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var record, tokenSecret, responseBodyResult, responseBody, error_2;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 4, , 5]);
                record = void 0;
                tokenSecret = process.env.TOKEN_SECRET;
                if (!(req.body.middlewareData.token.tokenType === "USER_REFRESH_TOKEN")) return [3 /*break*/, 2];
                return [4 /*yield*/, prisma.userAccessToken.create({
                        data: {
                            userId: req.body.middlewareData.token.userId,
                            token: jsonwebtoken_1["default"].sign({ userId: req.body.middlewareData.token.userId, tokenType: "USER_ACCESS_TOKEN" }, tokenSecret, { expiresIn: '1d' }),
                            expiresAt: new Date(Date.now() + 600000),
                            userRefreshTokenId: req.body.middlewareData.token.id
                        }
                    })];
            case 1:
                record = _a.sent();
                return [3 /*break*/, 3];
            case 2: throw new HTTPError_1.BadRequestError("Invalid token type");
            case 3:
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_CREATED, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody(record, responseBodyResult);
                res.status(200).json(responseBody);
                return [3 /*break*/, 5];
            case 4:
                error_2 = _a.sent();
                next(error_2);
                return [3 /*break*/, 5];
            case 5: return [2 /*return*/];
        }
    });
}); };
exports.findUserToken = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var record, responseBodyResult, responseBody, error_3;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 6, , 7]);
                record = void 0;
                if (!(req.body.middlewareData.token.tokenType === "USER_ACCESS_TOKEN")) return [3 /*break*/, 2];
                return [4 /*yield*/, prisma.userAccessToken.findUnique({
                        where: {
                            token: req.body.middlewareData.token.token
                        }
                    })];
            case 1:
                record = _a.sent();
                return [3 /*break*/, 5];
            case 2:
                if (!(req.body.middlewareData.token.tokenType === "USER_REFRESH_TOKEN")) return [3 /*break*/, 4];
                return [4 /*yield*/, prisma.userRefreshToken.findUnique({
                        where: {
                            token: req.body.middlewareData.token.token
                        }
                    })];
            case 3:
                record = _a.sent();
                return [3 /*break*/, 5];
            case 4: throw new HTTPError_1.BadRequestError("Invalid token type");
            case 5:
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_CHECKED, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody(record, responseBodyResult);
                res.status(200).json(responseBody);
                return [3 /*break*/, 7];
            case 6:
                error_3 = _a.sent();
                next(error_3);
                return [3 /*break*/, 7];
            case 7: return [2 /*return*/];
        }
    });
}); };
exports.deactivateUserToken = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var record, responseBodyResult, responseBody, error_4;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 6, , 7]);
                record = void 0;
                if (!(req.body.middlewareData.token.tokenType === "USER_ACCESS_TOKEN")) return [3 /*break*/, 2];
                return [4 /*yield*/, prisma.userAccessToken.update({
                        where: { id: req.body.middlewareData.token.id },
                        data: { active: false }
                    })];
            case 1:
                record = _a.sent();
                return [3 /*break*/, 5];
            case 2:
                if (!(req.body.middlewareData.token.tokenType === "USER_REFRESH_TOKEN")) return [3 /*break*/, 4];
                return [4 /*yield*/, prisma.userRefreshToken.update({
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
                res.status(200).json(responseBody);
                return [3 /*break*/, 7];
            case 6:
                error_4 = _a.sent();
                next(error_4);
                return [3 /*break*/, 7];
            case 7: return [2 /*return*/];
        }
    });
}); };
