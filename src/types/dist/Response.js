"use strict";
exports.__esModule = true;
exports.ResultTitle = exports.ResultStatus = exports.ResultType = exports.ResponseBody = exports.ResponseBodyRresult = void 0;
var ResponseBodyRresult = /** @class */ (function () {
    function ResponseBodyRresult(message, type, status, instance) {
        this.message = message;
        this.type = type;
        this.status = status;
        this.instance = instance;
    }
    return ResponseBodyRresult;
}());
exports.ResponseBodyRresult = ResponseBodyRresult;
var ResponseBody = /** @class */ (function () {
    function ResponseBody(data, result) {
        this.data = data;
        this.result = result;
    }
    return ResponseBody;
}());
exports.ResponseBody = ResponseBody;
var ResultType;
(function (ResultType) {
    ResultType["ERROR"] = "error";
    ResultType["SUCCESS"] = "success";
    ResultType["WARNING"] = "warning";
    ResultType["INFO"] = "info";
})(ResultType = exports.ResultType || (exports.ResultType = {}));
var ResultStatus;
(function (ResultStatus) {
    ResultStatus[ResultStatus["OK"] = 200] = "OK";
    ResultStatus[ResultStatus["CREATED"] = 201] = "CREATED";
    ResultStatus[ResultStatus["ACCEPTED"] = 202] = "ACCEPTED";
    ResultStatus[ResultStatus["BAD_REQUEST"] = 400] = "BAD_REQUEST";
    ResultStatus[ResultStatus["UNAUTHORIZED"] = 401] = "UNAUTHORIZED";
    ResultStatus[ResultStatus["FORBIDDEN"] = 403] = "FORBIDDEN";
    ResultStatus[ResultStatus["NOT_FOUND"] = 404] = "NOT_FOUND";
    ResultStatus[ResultStatus["CONFLICT"] = 409] = "CONFLICT";
    ResultStatus[ResultStatus["INTERNAL_SERVER_ERROR"] = 500] = "INTERNAL_SERVER_ERROR";
})(ResultStatus = exports.ResultStatus || (exports.ResultStatus = {}));
var ResultTitle;
(function (ResultTitle) {
    ResultTitle["NO_PERMISSIONS"] = "No permissions";
    ResultTitle["RECORD_CREATED"] = "Record created";
    ResultTitle["RECORD_UPDATED"] = "Record updated";
    ResultTitle["RECORD_FOUND"] = "Record found";
    ResultTitle["RECORDS_FOUND"] = "Records found";
    ResultTitle["RECORD_DELETED"] = "Record deleted";
    ResultTitle["RECORD_ACTIVATED"] = "Record activated";
    ResultTitle["RECORD_DEACTIVATED"] = "Record deactivated";
    ResultTitle["RECORD_CHECKED"] = "Record checked";
    ResultTitle["INTERNAL_SERVER_ERROR"] = "Internal server error";
    ResultTitle["BAD_REQUEST"] = "Bad request";
    ResultTitle["UNAUTHORIZED"] = "Unauthorized";
    ResultTitle["NOT_FOUND"] = "Not found";
    ResultTitle["CONFLICT"] = "Conflict";
})(ResultTitle = exports.ResultTitle || (exports.ResultTitle = {}));
