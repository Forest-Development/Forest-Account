"use strict";
exports.__esModule = true;
exports.deactiveUserSchema = exports.verifyUserSchema = exports.deleteUserSchema = exports.updateUserSchema = exports.findUserSchema = exports.findUsersSchema = exports.createUserSchema = void 0;
var Joi = require('joi');
exports.createUserSchema = Joi.object({
    firstName: Joi.string().min(3).max(30).required(),
    lastName: Joi.string().min(3).max(30).required(),
    nickname: Joi.string().min(3).max(30).required(),
    email: Joi.string().email().lowercase().required(),
    phone: Joi.string().min(9).max(14).required(),
    gender: Joi.string().required()
});
exports.findUsersSchema = Joi.object({});
exports.findUserSchema = Joi.object({});
exports.updateUserSchema = Joi.object({
    firstName: Joi.string().min(3).max(30).required(),
    lastName: Joi.string().min(3).max(30).required(),
    nickname: Joi.string().min(3).max(30).required(),
    email: Joi.string().email().lowercase().required(),
    phone: Joi.string().min(9).max(14).required(),
    gender: Joi.string().required()
});
exports.deleteUserSchema = Joi.object({});
exports.verifyUserSchema = Joi.object({
    code: Joi.string().required()
});
exports.deactiveUserSchema = Joi.object({
    code: Joi.string().required()
});
