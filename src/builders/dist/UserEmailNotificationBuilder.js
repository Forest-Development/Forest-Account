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
exports.UserEmailNotificationBuilder = void 0;
var path_1 = require("path");
var nodemailer = require('nodemailer');
var hbs = require('nodemailer-express-handlebars');
var client_1 = require("@prisma/client");
var prisma = new client_1.PrismaClient();
var UserEmailNotificationBuilder = /** @class */ (function () {
    function UserEmailNotificationBuilder() {
        this.userEmailNotification = {
            userId: '',
            subject: '',
            template: '',
            context: {}
        };
    }
    UserEmailNotificationBuilder.prototype.withUserId = function (userId) {
        this.userEmailNotification.userId = userId;
        return this;
    };
    UserEmailNotificationBuilder.prototype.withSubject = function (subject) {
        this.userEmailNotification.subject = 'Forest - ' + subject;
        return this;
    };
    UserEmailNotificationBuilder.prototype.withTemplate = function (template) {
        this.userEmailNotification.template = template;
        return this;
    };
    UserEmailNotificationBuilder.prototype.withContext = function (context) {
        this.userEmailNotification.context = context;
        return this;
    };
    UserEmailNotificationBuilder.prototype.get = function () {
        return this.userEmailNotification;
    };
    UserEmailNotificationBuilder.prototype.save = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, prisma.userEmailNotification.create({
                            data: this.userEmailNotification
                        })];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    UserEmailNotificationBuilder.prototype.send = function () {
        return __awaiter(this, void 0, void 0, function () {
            var user, transporterOptions, hbsOptions, mailOptions;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, prisma.user.findUnique({
                            where: {
                                id: this.userEmailNotification.userId
                            }
                        })];
                    case 1:
                        user = _a.sent();
                        transporterOptions = {
                            service: 'gmail',
                            auth: {
                                user: process.env.NODEMAILER_AUTH_USER,
                                pass: process.env.NODEMAILER_AUTH_PASS
                            }
                        };
                        hbsOptions = {
                            viewEngine: {
                                extName: '.handlebars',
                                layoutsDir: path_1["default"].resolve(__dirname, '../emails/views/'),
                                defaultLayout: false,
                                partialsDir: path_1["default"].resolve(__dirname, '../emails/components/')
                            },
                            viewPath: path_1["default"].resolve(__dirname, '../emails/views/'),
                            extName: '.handlebars'
                        };
                        mailOptions = {
                            from: 'noreply.forest.development@gmail.com',
                            to: user.email,
                            subject: this.userEmailNotification.subject,
                            template: this.userEmailNotification.template,
                            context: this.userEmailNotification.context,
                            attachments: [
                                {
                                    filename: 'logo.png',
                                    path: path_1["default"].resolve(__dirname, '../emails/assets/logo.png'),
                                    cid: 'logo'
                                }
                            ]
                        };
                        nodemailer
                            .createTransport(transporterOptions)
                            .use('compile', hbs(hbsOptions))
                            .sendMail(mailOptions).then(function (info) { return __awaiter(_this, void 0, void 0, function () {
                            return __generator(this, function (_a) {
                                switch (_a.label) {
                                    case 0: return [4 /*yield*/, prisma.userEmailNotification.create({
                                            data: this.userEmailNotification
                                        })];
                                    case 1: return [2 /*return*/, _a.sent()];
                                }
                            });
                        }); });
                        return [2 /*return*/];
                }
            });
        });
    };
    return UserEmailNotificationBuilder;
}());
exports.UserEmailNotificationBuilder = UserEmailNotificationBuilder;
