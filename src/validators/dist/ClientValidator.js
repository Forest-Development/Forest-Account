"use strict";
exports.__esModule = true;
exports.deleteClientSchema = exports.updateClientSchema = exports.findClientSchema = exports.findClientsSchema = exports.createClientSchema = void 0;
var Joi = require('joi');
exports.createClientSchema = Joi.object({
    name: Joi.string().min(3).max(30).required(),
    redirectUri: Joi.string().uri().required()
});
exports.findClientsSchema = Joi.object({});
exports.findClientSchema = Joi.object({});
exports.updateClientSchema = Joi.object({
    name: Joi.string().min(3).max(30).required(),
    redirectUri: Joi.string().uri().required()
});
exports.deleteClientSchema = Joi.object({});
