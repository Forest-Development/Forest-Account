"use strict";
exports.__esModule = true;
exports.deleteRolePermissionSchema = exports.updateRolePermissionSchema = exports.findRolePermissionSchema = exports.findRolePermissionsSchema = exports.createRolePermissionSchema = void 0;
var Joi = require('joi');
exports.createRolePermissionSchema = Joi.object({
    roleId: Joi.number().required(),
    permissionId: Joi.number().required()
});
exports.findRolePermissionsSchema = Joi.object({});
exports.findRolePermissionSchema = Joi.object({});
exports.updateRolePermissionSchema = Joi.object({
    roleId: Joi.number().required(),
    permissionId: Joi.number().required()
});
exports.deleteRolePermissionSchema = Joi.object({});
