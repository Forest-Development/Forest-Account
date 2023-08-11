"use strict";
exports.__esModule = true;
exports.handleError = void 0;
var Response_1 = require("../types/Response");
exports.handleError = function (error, req, res, next) {
    var responseError = error;
    var status = responseError.status || Response_1.ResultStatus.INTERNAL_SERVER_ERROR;
    var message = responseError.message || Response_1.ResultTitle.INTERNAL_SERVER_ERROR;
    var detail = responseError.detail || 'No detail';
    var responseBody = {
        result: {
            type: Response_1.ResultType.ERROR,
            status: status,
            title: message,
            detail: detail,
            instance: req.originalUrl
        }
    };
    res.status(status).json(responseBody);
};
