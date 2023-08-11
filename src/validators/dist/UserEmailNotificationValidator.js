"use strict";
exports.__esModule = true;
exports.deleteUserEmailNotificationSchema = exports.updateUserEmailNotificationSchema = exports.findUserEmailNotificationSchema = exports.findUserEmailNotificationsSchema = exports.createUserEmailNotificationSchema = void 0;
var Joi = require('joi');
exports.createUserEmailNotificationSchema = Joi.object({
    userId: Joi.number().required(),
    emailNotificationId: Joi.number().required()
});
exports.findUserEmailNotificationsSchema = Joi.object({});
exports.findUserEmailNotificationSchema = Joi.object({});
exports.updateUserEmailNotificationSchema = Joi.object({
    userId: Joi.number().required(),
    emailNotificationId: Joi.number().required()
});
exports.deleteUserEmailNotificationSchema = Joi.object({});
