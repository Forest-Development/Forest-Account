"use strict";
exports.__esModule = true;
exports.ResultTitle = exports.ResultStatus = exports.ResultType = void 0;
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
    ResultStatus[ResultStatus["NOT_FOUND"] = 404] = "NOT_FOUND";
    ResultStatus[ResultStatus["CONFLICT"] = 409] = "CONFLICT";
    ResultStatus[ResultStatus["INTERNAL_SERVER_ERROR"] = 500] = "INTERNAL_SERVER_ERROR";
})(ResultStatus = exports.ResultStatus || (exports.ResultStatus = {}));
var ResultTitle;
(function (ResultTitle) {
    ResultTitle["INTERNAL_SERVER_ERROR"] = "Internal server error";
    ResultTitle["RECORD_CREATED"] = "Record created";
    ResultTitle["RECORD_UPDATED"] = "Record updated";
    ResultTitle["RECORD_FOUND"] = "Record found";
    ResultTitle["RECORDS_FOUND"] = "Records found";
    ResultTitle["RECORD_DELETED"] = "Record deleted";
    ResultTitle["BAD_REQUEST"] = "Bad request";
    ResultTitle["UNAUTHORIZED"] = "Unauthorized";
    ResultTitle["NOT_FOUND"] = "Not found";
    ResultTitle["CONFLICT"] = "Conflict";
})(ResultTitle = exports.ResultTitle || (exports.ResultTitle = {}));
