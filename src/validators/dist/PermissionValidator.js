"use strict";
exports.__esModule = true;
exports.deletePermissionSchema = exports.updatePermissionSchema = exports.findPermissionSchema = exports.findPermissionsSchema = exports.createPermissionSchema = void 0;
var Joi = require('joi');
exports.createPermissionSchema = Joi.object({
    name: Joi.string().min(3).max(30).required(),
    description: Joi.string().min(3).max(30)
});
exports.findPermissionsSchema = Joi.object({});
exports.findPermissionSchema = Joi.object({});
exports.updatePermissionSchema = Joi.object({
    name: Joi.string().min(3).max(30).required(),
    description: Joi.string().min(3).max(30)
});
exports.deletePermissionSchema = Joi.object({});
