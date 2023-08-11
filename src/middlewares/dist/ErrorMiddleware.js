"use strict";
exports.__esModule = true;
exports.handleNotFound = exports.handleError = void 0;
var HTTPResponse_1 = require("../types/HTTPResponse");
var HTTPError_1 = require("../types/HTTPError");
exports.handleError = function (error, req, res, next) {
    var responseError = error;
    var message = responseError.message || HTTPError_1.HTTPErrorMessage.INTERNAL_SERVER_ERROR;
    var status = responseError.status || HTTPError_1.HTTPErrorStatus.INTERNAL_SERVER_ERROR;
    var responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(message, HTTPError_1.HTTPErrorType, status, req.originalUrl);
    var responseBody = new HTTPResponse_1.HTTPResponseBody(undefined, responseBodyResult);
    res.status(status).json(responseBody);
};
exports.handleNotFound = function (req, res, next) {
    var responseBodyResult = new HTTPResponse_1.HTTPResponseBodyResult(HTTPError_1.HTTPErrorMessage.NOT_FOUND, HTTPError_1.HTTPErrorType, HTTPError_1.HTTPErrorStatus.NOT_FOUND, req.originalUrl);
    var responseBody = new HTTPResponse_1.HTTPResponseBody(undefined, responseBodyResult);
    res.status(HTTPError_1.HTTPErrorStatus.NOT_FOUND).json(responseBody);
};
