"use strict";
exports.__esModule = true;
exports.deleteUserDeactivationCodeSchema = exports.updateUserDeactivationCodeSchema = exports.findUserDeactivationCodeSchema = exports.findUserDeactivationCodesSchema = exports.createUserDeactivationCodeSchema = void 0;
var Joi = require('joi');
exports.createUserDeactivationCodeSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.findUserDeactivationCodesSchema = Joi.object({});
exports.findUserDeactivationCodeSchema = Joi.object({});
exports.updateUserDeactivationCodeSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.deleteUserDeactivationCodeSchema = Joi.object({});
