"use strict";
exports.__esModule = true;
exports.deleteRoleSchema = exports.updateRoleSchema = exports.findRoleSchema = exports.findRolesSchema = exports.createRoleSchema = void 0;
var Joi = require('joi');
exports.createRoleSchema = Joi.object({
    name: Joi.string().min(3).max(30).required(),
    description: Joi.string().min(3).max(30),
    isDefault: Joi.boolean().required()
});
exports.findRolesSchema = Joi.object({});
exports.findRoleSchema = Joi.object({});
exports.updateRoleSchema = Joi.object({
    name: Joi.string().min(3).max(30).required(),
    description: Joi.string().min(3).max(30)
});
exports.deleteRoleSchema = Joi.object({});
