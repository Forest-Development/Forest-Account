"use strict";
exports.__esModule = true;
exports.createUserPasswordSchema = exports.deactivateUserPasswordCodeSchema = exports.checkUserPasswordCodeSchema = exports.createUserPasswordCodeSchema = void 0;
var Joi = require('joi');
exports.createUserPasswordCodeSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.checkUserPasswordCodeSchema = Joi.object({
    code: Joi.string().required().length(8).pattern(/^F-\d{6}$/)
});
exports.deactivateUserPasswordCodeSchema = Joi.object({
    code: Joi.string().required().length(8).pattern(/^F-\d{6}$/)
});
exports.createUserPasswordSchema = Joi.object({
    code: Joi.string().required().length(8).pattern(/^F-\d{6}$/),
    password: Joi.string().min(5).required()
});
