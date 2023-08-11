"use strict";
exports.__esModule = true;
exports.deactivateUserAccessTokenSchema = exports.findUserAccessTokenSchema = exports.refreshUserAccessTokenSchema = exports.createUserAccessTokenSchema = void 0;
var Joi = require('joi');
exports.createUserAccessTokenSchema = Joi.object({
    email: Joi.string().email().lowercase().required(),
    password: Joi.string().min(5).required()
});
exports.refreshUserAccessTokenSchema = Joi.object({});
exports.findUserAccessTokenSchema = Joi.object({});
exports.deactivateUserAccessTokenSchema = Joi.object({});
