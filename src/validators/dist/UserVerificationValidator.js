"use strict";
exports.__esModule = true;
exports.checkUserVerificationCodeSchema = exports.createUserVerificationCodeSchema = void 0;
var Joi = require('joi');
exports.createUserVerificationCodeSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.checkUserVerificationCodeSchema = Joi.object({
    code: Joi.string().required().length(8).pattern(/^F-\d{6}$/)
});
