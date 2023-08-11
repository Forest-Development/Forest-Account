"use strict";
exports.__esModule = true;
exports.deleteClientAllowedScopeSchema = exports.updateClientAllowedScopeSchema = exports.findClientAllowedScopeSchema = exports.findClientAllowedScopesSchema = exports.createClientAllowedScopeSchema = void 0;
var Joi = require('joi');
exports.createClientAllowedScopeSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.findClientAllowedScopesSchema = Joi.object({});
exports.findClientAllowedScopeSchema = Joi.object({});
exports.updateClientAllowedScopeSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.deleteClientAllowedScopeSchema = Joi.object({});
