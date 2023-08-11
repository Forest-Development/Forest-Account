"use strict";
exports.__esModule = true;
exports.checkUserDeactivationCodeSchema = exports.createUserDeactivationCodeSchema = void 0;
var Joi = require('joi');
exports.createUserDeactivationCodeSchema = Joi.object({
    email: Joi.string().email().lowercase().required()
});
exports.checkUserDeactivationCodeSchema = Joi.object({
    code: Joi.string().required().length(8).pattern(/^F-\d{6}$/)
});
