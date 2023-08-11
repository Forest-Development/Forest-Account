"use strict";
exports.__esModule = true;
exports.HTTPResponseBody = exports.HTTPResponseBodyResult = void 0;
var HTTPResponseBodyResult = /** @class */ (function () {
    function HTTPResponseBodyResult(message, type, status, instance) {
        this.message = message;
        this.type = type;
        this.status = status;
        this.instance = instance;
    }
    return HTTPResponseBodyResult;
}());
exports.HTTPResponseBodyResult = HTTPResponseBodyResult;
var HTTPResponseBody = /** @class */ (function () {
    function HTTPResponseBody(data, result) {
        this.data = data;
        this.result = result;
    }
    return HTTPResponseBody;
}());
exports.HTTPResponseBody = HTTPResponseBody;
