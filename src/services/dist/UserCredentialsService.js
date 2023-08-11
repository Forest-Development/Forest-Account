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
exports.createUserPassword = exports.deactivateUserPasswordCode = exports.checkUserPasswordCode = exports.processUserPasswordCode = exports.createUserPasswordCode = void 0;
var client_1 = require("@prisma/client");
var Response_1 = require("../types/Response");
var bcrypt = require("bcrypt");
var dotenv_1 = require("dotenv");
dotenv_1["default"].config();
var prisma = new client_1.PrismaClient();
exports.createUserPasswordCode = function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var user, record, responseBody, error_1;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                return [4 /*yield*/, prisma.user.findUnique({
                        where: {
                            id: req.body.data.id
                        }
                    })];
            case 1:
                user = _a.sent();
                if (!user) {
                    throw new Response_1.ResponseError("User not found", "Check user ID", 404);
                }
                if (user.active === false) {
                    throw new Response_1.ResponseError("User already deactivated", "Check user ID", 404);
                }
                record = exports.processUserPasswordCode(user);
                responseBody = {
                    data: {
                        id: record.id,
                        createdAt: record.createdAt,
                        updatedAt: record.updatedAt,
                        userId: record.userId,
                        expiresAt: record.expiresAt
                    },
                    result: {
                        type: Response_1.ResultType.SUCCESS,
                        status: Response_1.ResultStatus.CREATED,
                        title: Response_1.ResultTitle.RECORD_CREATED,
                        detail: "Record created",
                        instance: req.originalUrl
                    }
                };
                res.status(201).json(responseBody);
                return [3 /*break*/, 3];
            case 2:
                error_1 = _a.sent();
                throw error_1;
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.processUserPasswordCode = function (user) { return __awaiter(void 0, void 0, Promise, function () {
    var record, nodemailer, transporter, mailOptions;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0: return [4 /*yield*/, prisma.userPasswordCode.create({
                    data: {
                        userId: user.id,
                        code: Math.floor(100000 + Math.random() * 900000).toString(),
                        expiresAt: new Date(Date.now() + 600000)
                    }
                })];
            case 1:
                record = _a.sent();
                nodemailer = require('nodemailer');
                transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: 'jalabendowicz@gmail.com',
                        pass: 'yourpassword'
                    }
                });
                mailOptions = {
                    from: 'jalabendowicz@gmail.com',
                    to: user.email,
                    subject: 'Pasword code',
                    text: record.code
                };
                transporter.sendMail(mailOptions);
                return [2 /*return*/, record];
        }
    });
}); };
exports.checkUserPasswordCode = function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var userPasswordCode, responseBody, error_2;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                return [4 /*yield*/, prisma.userPasswordCode.findUnique({
                        where: {
                            code: req.body.data.code
                        }
                    })];
            case 1:
                userPasswordCode = _a.sent();
                if (!userPasswordCode) {
                    throw new Response_1.ResponseError("Code not found", "Check code", 404);
                }
                if (userPasswordCode.active === false) {
                    throw new Response_1.ResponseError("Code already deactivated", "Code token", 404);
                }
                if (userPasswordCode.expiresAt < new Date()) {
                    throw new Response_1.ResponseError("Code expired", "Check code", 404);
                }
                responseBody = {
                    data: userPasswordCode,
                    result: {
                        type: Response_1.ResultType.SUCCESS,
                        status: Response_1.ResultStatus.OK,
                        title: Response_1.ResultTitle.RECORD_CHECKED,
                        detail: "Record checked",
                        instance: req.originalUrl
                    }
                };
                res.status(201).json(responseBody);
                return [3 /*break*/, 3];
            case 2:
                error_2 = _a.sent();
                throw error_2;
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.deactivateUserPasswordCode = function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var userPasswordCode, record, responseBody, error_3;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                return [4 /*yield*/, prisma.userPasswordCode.findUnique({
                        where: {
                            code: req.body.data.code
                        }
                    })];
            case 1:
                userPasswordCode = _a.sent();
                if (!userPasswordCode) {
                    throw new Response_1.ResponseError("Code not found", "Check code", 404);
                }
                if (userPasswordCode.active === false) {
                    throw new Response_1.ResponseError("Code already deactivated", "Code token", 404);
                }
                if (userPasswordCode.expiresAt < new Date()) {
                    throw new Response_1.ResponseError("Code expired", "Check code", 404);
                }
                return [4 /*yield*/, prisma.userPasswordCode.update({
                        where: { id: userPasswordCode.id },
                        data: { active: false }
                    })];
            case 2:
                record = _a.sent();
                responseBody = {
                    data: record,
                    result: {
                        type: Response_1.ResultType.SUCCESS,
                        status: Response_1.ResultStatus.OK,
                        title: Response_1.ResultTitle.RECORD_DEACTIVATED,
                        detail: "Record deactivated",
                        instance: req.originalUrl
                    }
                };
                res.status(201).json(responseBody);
                return [3 /*break*/, 4];
            case 3:
                error_3 = _a.sent();
                throw error_3;
            case 4: return [2 /*return*/];
        }
    });
}); };
exports.createUserPassword = function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var userPasswordCode, salt, hashPassword, record, responseBody, error_4;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 5, , 6]);
                return [4 /*yield*/, prisma.userPasswordCode.findUnique({
                        where: {
                            code: req.body.data.code
                        }
                    })];
            case 1:
                userPasswordCode = _a.sent();
                if (!userPasswordCode) {
                    throw new Response_1.ResponseError("Code not found", "Code token", 404);
                }
                if (userPasswordCode.active === false) {
                    throw new Response_1.ResponseError("Code already deactivated", "Code token", 404);
                }
                if (userPasswordCode.expiresAt < new Date()) {
                    throw new Response_1.ResponseError("Code expired", "Code token", 404);
                }
                return [4 /*yield*/, bcrypt.genSalt(Number(process.env.SALT))];
            case 2:
                salt = _a.sent();
                return [4 /*yield*/, bcrypt.hash(req.body.data.password, salt)];
            case 3:
                hashPassword = _a.sent();
                return [4 /*yield*/, prisma.userPassword.create({
                        data: {
                            userId: userPasswordCode.userId,
                            passwordHash: hashPassword,
                            userPasswordCodeId: userPasswordCode.id
                        }
                    })];
            case 4:
                record = _a.sent();
                responseBody = {
                    data: record,
                    result: {
                        type: Response_1.ResultType.SUCCESS,
                        status: Response_1.ResultStatus.CREATED,
                        title: Response_1.ResultTitle.RECORD_CREATED,
                        detail: "Record created",
                        instance: req.originalUrl
                    }
                };
                res.status(201).json(responseBody);
                return [3 /*break*/, 6];
            case 5:
                error_4 = _a.sent();
                throw error_4;
            case 6: return [2 /*return*/];
        }
    });
}); };
