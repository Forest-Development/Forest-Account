"use strict";
exports.__esModule = true;
exports.deleteUserPasswordCodeSchema = exports.updateUserPasswordCodeSchema = exports.findUserPasswordCodeSchema = exports.findUserPasswordCodesSchema = exports.createUserPasswordCodeSchema = void 0;
var Joi = require('joi');
exports.createUserPasswordCodeSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.findUserPasswordCodesSchema = Joi.object({});
exports.findUserPasswordCodeSchema = Joi.object({});
exports.updateUserPasswordCodeSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.deleteUserPasswordCodeSchema = Joi.object({});
