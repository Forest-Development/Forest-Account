"use strict";
exports.__esModule = true;
exports.deleteClientScopeSchema = exports.updateClientScopeSchema = exports.findClientScopeSchema = exports.findClientScopesSchema = exports.createClientScopeSchema = void 0;
var Joi = require('joi');
exports.createClientScopeSchema = Joi.object({
    clientId: Joi.number().required(),
    scopeId: Joi.number().required()
});
exports.findClientScopesSchema = Joi.object({});
exports.findClientScopeSchema = Joi.object({});
exports.updateClientScopeSchema = Joi.object({
    clientId: Joi.number().required(),
    scopeId: Joi.number().required()
});
exports.deleteClientScopeSchema = Joi.object({});
