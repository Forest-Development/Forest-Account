"use strict";
exports.__esModule = true;
exports.deleteScopeSchema = exports.updateScopeSchema = exports.findScopeSchema = exports.findScopesSchema = exports.createScopeSchema = void 0;
var Joi = require('joi');
exports.createScopeSchema = Joi.object({
    name: Joi.string().min(3).max(30).required(),
    description: Joi.string().min(3).max(30),
    isDefault: Joi.boolean().required()
});
exports.findScopesSchema = Joi.object({});
exports.findScopeSchema = Joi.object({});
exports.updateScopeSchema = Joi.object({
    name: Joi.string().min(3).max(30).required(),
    description: Joi.string().min(3).max(30)
});
exports.deleteScopeSchema = Joi.object({});
