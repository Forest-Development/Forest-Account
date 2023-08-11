"use strict";
exports.__esModule = true;
exports.deleteUserPasswordSchema = exports.updateUserPasswordSchema = exports.findUserPasswordSchema = exports.findUserPasswordsSchema = exports.createUserPasswordSchema = void 0;
var Joi = require('joi');
exports.createUserPasswordSchema = Joi.object({
    code: Joi.string().required(),
    password: Joi.string().required()
});
exports.findUserPasswordsSchema = Joi.object({});
exports.findUserPasswordSchema = Joi.object({});
exports.updateUserPasswordSchema = Joi.object({
    password: Joi.string().required()
});
exports.deleteUserPasswordSchema = Joi.object({});
