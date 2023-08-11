"use strict";
exports.__esModule = true;
exports.getResponseBodyResult = exports.getInternalServerErrorResponseBodyResult = exports.getConflictResponseBodyResult = exports.getNotFoundResponseBodyResult = exports.getUnauthorizedResponseBodyResult = exports.getBadRequestResponseBodyResult = exports.getRecordDeletedResponseBodyResult = exports.getRecordsFoundResponseBodyResult = exports.getRecordFoundResponseBodyResult = exports.getRecordUpdatedResponseBodyResult = exports.getRecordCreatedResponseBodyResult = exports.RESPONSE_BODY_RESULT_STATUS_INTERNAL_SERVER_ERROR = exports.RESPONSE_BODY_RESULT_STATUS_CONFLICT = exports.RESPONSE_BODY_RESULT_STATUS_NOT_FOUND = exports.RESPONSE_BODY_RESULT_STATUS_UNAUTHORIZED = exports.RESPONSE_BODY_RESULT_STATUS_BAD_REQUEST = exports.RESPONSE_BODY_RESULT_STATUS_ACCEPTED = exports.RESPONSE_BODY_RESULT_STATUS_CREATED = exports.RESPONSE_BODY_RESULT_STATUS_OK = exports.RESPONSE_BODY_RESULT_TITLE_INTERNAL_SERVER_ERROR = exports.RESPONSE_BODY_RESULT_TITLE_CONFLICT = exports.RESPONSE_BODY_RESULT_TITLE_NOT_FOUND = exports.RESPONSE_BODY_RESULT_TITLE_UNAUTHORIZED = exports.RESPONSE_BODY_RESULT_TITLE_BAD_REQUEST = exports.RESPONSE_BODY_RESULT_TITLE_RECORD_DELETED = exports.RESPONSE_BODY_RESULT_TITLE_RECORDS_FOUND = exports.RESPONSE_BODY_RESULT_TITLE_RECORD_FOUND = exports.RESPONSE_BODY_RESULT_TITLE_RECORD_UPDATED = exports.RESPONSE_BODY_RESULT_TITLE_RECORD_CREATED = exports.RESPONSE_BODY_RESULT_TYPE_INFO = exports.RESPONSE_BODY_RESULT_TYPE_WARNING = exports.RESPONSE_BODY_RESULT_TYPE_ERROR = exports.RESPONSE_BODY_RESULT_TYPE_SUCCESS = void 0;
/**
 * @description Represents the type of a response body result.
 */
exports.RESPONSE_BODY_RESULT_TYPE_SUCCESS = 'success';
exports.RESPONSE_BODY_RESULT_TYPE_ERROR = 'error';
exports.RESPONSE_BODY_RESULT_TYPE_WARNING = 'warning';
exports.RESPONSE_BODY_RESULT_TYPE_INFO = 'info';
/**
 * @description Represents the title of a response body result.
 */
exports.RESPONSE_BODY_RESULT_TITLE_RECORD_CREATED = 'Record created';
exports.RESPONSE_BODY_RESULT_TITLE_RECORD_UPDATED = 'Record updated';
exports.RESPONSE_BODY_RESULT_TITLE_RECORD_FOUND = 'Record found';
exports.RESPONSE_BODY_RESULT_TITLE_RECORDS_FOUND = 'Records found';
exports.RESPONSE_BODY_RESULT_TITLE_RECORD_DELETED = 'Record deleted';
exports.RESPONSE_BODY_RESULT_TITLE_BAD_REQUEST = 'Bad request';
exports.RESPONSE_BODY_RESULT_TITLE_UNAUTHORIZED = 'Unauthorized';
exports.RESPONSE_BODY_RESULT_TITLE_NOT_FOUND = 'Not found';
exports.RESPONSE_BODY_RESULT_TITLE_CONFLICT = 'Conflict';
exports.RESPONSE_BODY_RESULT_TITLE_INTERNAL_SERVER_ERROR = 'Internal server error';
/**
 * @description Represents the status of a response body result.
 */
exports.RESPONSE_BODY_RESULT_STATUS_OK = 200;
exports.RESPONSE_BODY_RESULT_STATUS_CREATED = 201;
exports.RESPONSE_BODY_RESULT_STATUS_ACCEPTED = 202;
exports.RESPONSE_BODY_RESULT_STATUS_BAD_REQUEST = 400;
exports.RESPONSE_BODY_RESULT_STATUS_UNAUTHORIZED = 401;
exports.RESPONSE_BODY_RESULT_STATUS_NOT_FOUND = 404;
exports.RESPONSE_BODY_RESULT_STATUS_CONFLICT = 409;
exports.RESPONSE_BODY_RESULT_STATUS_INTERNAL_SERVER_ERROR = 500;
/**
 * @description Returns a ResponseBodyResult object with the type, title, status, detail and instance properties set.
 * @param {string} detail
 * @param {string} instance
 * @returns {ResponseBodyResult}
 */
exports.getRecordCreatedResponseBodyResult = function (detail, instance) {
    return {
        type: exports.RESPONSE_BODY_RESULT_TYPE_SUCCESS,
        title: exports.RESPONSE_BODY_RESULT_TITLE_RECORD_CREATED,
        status: exports.RESPONSE_BODY_RESULT_STATUS_CREATED,
        detail: detail,
        instance: instance
    };
};
exports.getRecordUpdatedResponseBodyResult = function (detail, instance) {
    return {
        type: exports.RESPONSE_BODY_RESULT_TYPE_SUCCESS,
        title: exports.RESPONSE_BODY_RESULT_TITLE_RECORD_UPDATED,
        status: exports.RESPONSE_BODY_RESULT_STATUS_OK,
        detail: detail,
        instance: instance
    };
};
exports.getRecordFoundResponseBodyResult = function (detail, instance) {
    return {
        type: exports.RESPONSE_BODY_RESULT_TYPE_SUCCESS,
        title: exports.RESPONSE_BODY_RESULT_TITLE_RECORD_FOUND,
        status: exports.RESPONSE_BODY_RESULT_STATUS_OK,
        detail: detail,
        instance: instance
    };
};
exports.getRecordsFoundResponseBodyResult = function (detail, instance) {
    return {
        type: exports.RESPONSE_BODY_RESULT_TYPE_SUCCESS,
        title: exports.RESPONSE_BODY_RESULT_TITLE_RECORDS_FOUND,
        status: exports.RESPONSE_BODY_RESULT_STATUS_OK,
        detail: detail,
        instance: instance
    };
};
exports.getRecordDeletedResponseBodyResult = function (detail, instance) {
    return {
        type: exports.RESPONSE_BODY_RESULT_TYPE_SUCCESS,
        title: exports.RESPONSE_BODY_RESULT_TITLE_RECORD_DELETED,
        status: exports.RESPONSE_BODY_RESULT_STATUS_OK,
        detail: detail,
        instance: instance
    };
};
exports.getBadRequestResponseBodyResult = function (detail, instance) {
    return {
        type: exports.RESPONSE_BODY_RESULT_TYPE_ERROR,
        title: exports.RESPONSE_BODY_RESULT_TITLE_BAD_REQUEST,
        status: exports.RESPONSE_BODY_RESULT_STATUS_BAD_REQUEST,
        detail: detail,
        instance: instance
    };
};
exports.getUnauthorizedResponseBodyResult = function (detail, instance) {
    return {
        type: exports.RESPONSE_BODY_RESULT_TYPE_ERROR,
        title: exports.RESPONSE_BODY_RESULT_TITLE_UNAUTHORIZED,
        status: exports.RESPONSE_BODY_RESULT_STATUS_UNAUTHORIZED,
        detail: detail,
        instance: instance
    };
};
exports.getNotFoundResponseBodyResult = function (detail, instance) {
    return {
        type: exports.RESPONSE_BODY_RESULT_TYPE_ERROR,
        title: exports.RESPONSE_BODY_RESULT_TITLE_NOT_FOUND,
        status: exports.RESPONSE_BODY_RESULT_STATUS_NOT_FOUND,
        detail: detail,
        instance: instance
    };
};
exports.getConflictResponseBodyResult = function (detail, instance) {
    return {
        type: exports.RESPONSE_BODY_RESULT_TYPE_ERROR,
        title: exports.RESPONSE_BODY_RESULT_TITLE_CONFLICT,
        status: exports.RESPONSE_BODY_RESULT_STATUS_CONFLICT,
        detail: detail,
        instance: instance
    };
};
exports.getInternalServerErrorResponseBodyResult = function (detail, instance) {
    return {
        type: exports.RESPONSE_BODY_RESULT_TYPE_ERROR,
        title: exports.RESPONSE_BODY_RESULT_TITLE_INTERNAL_SERVER_ERROR,
        status: exports.RESPONSE_BODY_RESULT_STATUS_INTERNAL_SERVER_ERROR,
        detail: detail,
        instance: instance
    };
};
exports.getResponseBodyResult = function (type, title, status, detail, instance) {
    return {
        type: type,
        title: title,
        status: status,
        detail: detail,
        instance: instance
    };
};
