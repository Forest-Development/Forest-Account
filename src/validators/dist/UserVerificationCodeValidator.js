"use strict";
exports.__esModule = true;
exports.deleteUserVerificationCodeSchema = exports.updateUserVerificationCodeSchema = exports.findUserVerificationCodeSchema = exports.findUserVerificationCodesSchema = exports.createUserVerificationCodeSchema = void 0;
var Joi = require('joi');
exports.createUserVerificationCodeSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.findUserVerificationCodesSchema = Joi.object({});
exports.findUserVerificationCodeSchema = Joi.object({});
exports.updateUserVerificationCodeSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.deleteUserVerificationCodeSchema = Joi.object({});
