"use strict";
exports.__esModule = true;
exports.HTTPSuccessStatus = exports.HTTPSuccessMessage = exports.HTTPSuccessType = void 0;
exports.HTTPSuccessType = "success";
var HTTPSuccessMessage;
(function (HTTPSuccessMessage) {
    HTTPSuccessMessage["RECORD_CREATED"] = "Record created";
    HTTPSuccessMessage["RECORD_UPDATED"] = "Record updated";
    HTTPSuccessMessage["RECORD_FOUND"] = "Record found";
    HTTPSuccessMessage["RECORDS_FOUND"] = "Records found";
    HTTPSuccessMessage["RECORD_DELETED"] = "Record deleted";
    HTTPSuccessMessage["RECORD_ACTIVATED"] = "Record activated";
    HTTPSuccessMessage["RECORD_DEACTIVATED"] = "Record deactivated";
    HTTPSuccessMessage["RECORD_CHECKED"] = "Record checked";
})(HTTPSuccessMessage = exports.HTTPSuccessMessage || (exports.HTTPSuccessMessage = {}));
var HTTPSuccessStatus;
(function (HTTPSuccessStatus) {
    HTTPSuccessStatus[HTTPSuccessStatus["OK"] = 200] = "OK";
    HTTPSuccessStatus[HTTPSuccessStatus["CREATED"] = 201] = "CREATED";
    HTTPSuccessStatus[HTTPSuccessStatus["ACCEPTED"] = 202] = "ACCEPTED";
})(HTTPSuccessStatus = exports.HTTPSuccessStatus || (exports.HTTPSuccessStatus = {}));
