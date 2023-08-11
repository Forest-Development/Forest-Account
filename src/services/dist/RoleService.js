"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
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
exports.deleteRole = exports.updateRole = exports.findRoles = exports.findRole = exports.createRole = void 0;
var client_1 = require("@prisma/client");
var HTTPResponse_1 = require("../types/HTTPResponse");
var HTTPSuccess_1 = require("../types/HTTPSuccess");
var HTTPError_1 = require("../types/HTTPError");
var prisma = new client_1.PrismaClient();
exports.createRole = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var role, record, responseBodyResult, responseBody, error_1;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                return [4 /*yield*/, prisma.role.findUnique({
                        where: {
                            name: req.body.data.name,
                            active: true
                        }
                    })];
            case 1:
                role = _a.sent();
                if (role) {
                    throw new HTTPError_1.ConflictError("Role already exists");
                }
                return [4 /*yield*/, prisma.role.create({
                        data: __assign({}, req.body.data)
                    })];
            case 2:
                record = _a.sent();
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_CREATED, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.CREATED, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody(record, responseBodyResult);
                res.status(200).json(responseBody);
                return [3 /*break*/, 4];
            case 3:
                error_1 = _a.sent();
                next(error_1);
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); };
exports.findRole = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var record, responseBodyResult, responseBody, error_2;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                return [4 /*yield*/, prisma.role.findUnique({
                        where: {
                            id: req.params.id
                        }
                    })];
            case 1:
                record = _a.sent();
                if (!record) {
                    throw new HTTPError_1.NotFoundError("Role not found");
                }
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_FOUND, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody(record, responseBodyResult);
                res.status(200).json(responseBody);
                return [3 /*break*/, 3];
            case 2:
                error_2 = _a.sent();
                next(error_2);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.findRoles = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var records, responseBodyResult, responseBody, error_3;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                return [4 /*yield*/, prisma.role.findMany()];
            case 1:
                records = _a.sent();
                if (records.length === 0) {
                    throw new HTTPError_1.NotFoundError("Role not found");
                }
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORDS_FOUND, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody(records, responseBodyResult);
                res.status(200).json(responseBody);
                return [3 /*break*/, 3];
            case 2:
                error_3 = _a.sent();
                next(error_3);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.updateRole = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var role, record, responseBodyResult, responseBody, error_4;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                return [4 /*yield*/, prisma.role.findUnique({
                        where: {
                            id: req.params.id
                        }
                    })];
            case 1:
                role = _a.sent();
                if (!role) {
                    throw new HTTPError_1.NotFoundError("Role not found");
                }
                return [4 /*yield*/, prisma.role.update({
                        where: {
                            id: req.params.id
                        },
                        data: __assign({}, req.body.data)
                    })];
            case 2:
                record = _a.sent();
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_UPDATED, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody(record, responseBodyResult);
                res.status(200).json(responseBody);
                return [3 /*break*/, 4];
            case 3:
                error_4 = _a.sent();
                next(error_4);
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); };
exports.deleteRole = function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var role, record, responseBodyResult, responseBody, error_5;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                return [4 /*yield*/, prisma.role.findUnique({
                        where: {
                            id: req.params.id
                        }
                    })];
            case 1:
                role = _a.sent();
                if (!role) {
                    throw new HTTPError_1.NotFoundError("Role not found");
                }
                return [4 /*yield*/, prisma.role["delete"]({
                        where: {
                            id: req.params.id
                        }
                    })];
            case 2:
                record = _a.sent();
                responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPSuccess_1.HTTPSuccessMessage.RECORD_DELETED, HTTPSuccess_1.HTTPSuccessType, HTTPSuccess_1.HTTPSuccessStatus.OK, req.originalUrl);
                responseBody = new HTTPResponse_1.HTTPResponseBody(record, responseBodyResult);
                res.status(200).json(responseBody);
                return [3 /*break*/, 4];
            case 3:
                error_5 = _a.sent();
                next(error_5);
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); };
