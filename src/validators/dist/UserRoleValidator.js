"use strict";
exports.__esModule = true;
exports.deleteUserRoleSchema = exports.updateUserRoleSchema = exports.findUserRoleSchema = exports.findUserRolesSchema = exports.createUserRoleSchema = void 0;
var Joi = require('joi');
exports.createUserRoleSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.findUserRolesSchema = Joi.object({});
exports.findUserRoleSchema = Joi.object({});
exports.updateUserRoleSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.deleteUserRoleSchema = Joi.object({});
