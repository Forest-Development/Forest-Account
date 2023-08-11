"use strict";
exports.__esModule = true;
exports.deleteScopePermissionSchema = exports.updateScopePermissionSchema = exports.findScopePermissionSchema = exports.findScopePermissionsSchema = exports.createScopePermissionSchema = void 0;
var Joi = require('joi');
exports.createScopePermissionSchema = Joi.object({
    scopeId: Joi.number().required(),
    permissionId: Joi.number().required()
});
exports.findScopePermissionsSchema = Joi.object({});
exports.findScopePermissionSchema = Joi.object({});
exports.updateScopePermissionSchema = Joi.object({
    scopeId: Joi.number().required(),
    permissionId: Joi.number().required()
});
exports.deleteScopePermissionSchema = Joi.object({});
