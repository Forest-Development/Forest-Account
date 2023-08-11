"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
exports.__esModule = true;
exports.InternalServerError = exports.ConflictError = exports.NotFoundError = exports.ForbiddenError = exports.UnauthorizedError = exports.BadRequestError = exports.HTTPError = exports.HTTPErrorStatus = exports.HTTPErrorMessage = exports.HTTPErrorType = void 0;
exports.HTTPErrorType = "error";
var HTTPErrorMessage;
(function (HTTPErrorMessage) {
    HTTPErrorMessage["BAD_REQUEST"] = "Bad request";
    HTTPErrorMessage["UNAUTHORIZED"] = "Unauthorized";
    HTTPErrorMessage["FORBIDDEN"] = "No permission";
    HTTPErrorMessage["NOT_FOUND"] = "Not found";
    HTTPErrorMessage["CONFLICT"] = "Conflict";
    HTTPErrorMessage["INTERNAL_SERVER_ERROR"] = "Internal server error";
})(HTTPErrorMessage = exports.HTTPErrorMessage || (exports.HTTPErrorMessage = {}));
var HTTPErrorStatus;
(function (HTTPErrorStatus) {
    HTTPErrorStatus[HTTPErrorStatus["BAD_REQUEST"] = 400] = "BAD_REQUEST";
    HTTPErrorStatus[HTTPErrorStatus["UNAUTHORIZED"] = 401] = "UNAUTHORIZED";
    HTTPErrorStatus[HTTPErrorStatus["FORBIDDEN"] = 403] = "FORBIDDEN";
    HTTPErrorStatus[HTTPErrorStatus["NOT_FOUND"] = 404] = "NOT_FOUND";
    HTTPErrorStatus[HTTPErrorStatus["CONFLICT"] = 409] = "CONFLICT";
    HTTPErrorStatus[HTTPErrorStatus["INTERNAL_SERVER_ERROR"] = 500] = "INTERNAL_SERVER_ERROR";
})(HTTPErrorStatus = exports.HTTPErrorStatus || (exports.HTTPErrorStatus = {}));
var HTTPError = /** @class */ (function (_super) {
    __extends(HTTPError, _super);
    function HTTPError(message, status) {
        var _this = _super.call(this, message) || this;
        _this.status = status;
        return _this;
    }
    return HTTPError;
}(Error));
exports.HTTPError = HTTPError;
var BadRequestError = /** @class */ (function (_super) {
    __extends(BadRequestError, _super);
    function BadRequestError(message) {
        if (message === void 0) { message = HTTPErrorMessage.BAD_REQUEST; }
        return _super.call(this, message, HTTPErrorStatus.BAD_REQUEST) || this;
    }
    return BadRequestError;
}(HTTPError));
exports.BadRequestError = BadRequestError;
var UnauthorizedError = /** @class */ (function (_super) {
    __extends(UnauthorizedError, _super);
    function UnauthorizedError(message) {
        if (message === void 0) { message = HTTPErrorMessage.UNAUTHORIZED; }
        return _super.call(this, message, HTTPErrorStatus.UNAUTHORIZED) || this;
    }
    return UnauthorizedError;
}(HTTPError));
exports.UnauthorizedError = UnauthorizedError;
var ForbiddenError = /** @class */ (function (_super) {
    __extends(ForbiddenError, _super);
    function ForbiddenError(message) {
        if (message === void 0) { message = HTTPErrorMessage.FORBIDDEN; }
        return _super.call(this, message, HTTPErrorStatus.FORBIDDEN) || this;
    }
    return ForbiddenError;
}(HTTPError));
exports.ForbiddenError = ForbiddenError;
var NotFoundError = /** @class */ (function (_super) {
    __extends(NotFoundError, _super);
    function NotFoundError(message) {
        if (message === void 0) { message = HTTPErrorMessage.NOT_FOUND; }
        return _super.call(this, message, HTTPErrorStatus.NOT_FOUND) || this;
    }
    return NotFoundError;
}(HTTPError));
exports.NotFoundError = NotFoundError;
var ConflictError = /** @class */ (function (_super) {
    __extends(ConflictError, _super);
    function ConflictError(message) {
        if (message === void 0) { message = HTTPErrorMessage.CONFLICT; }
        return _super.call(this, message, HTTPErrorStatus.CONFLICT) || this;
    }
    return ConflictError;
}(HTTPError));
exports.ConflictError = ConflictError;
var InternalServerError = /** @class */ (function (_super) {
    __extends(InternalServerError, _super);
    function InternalServerError(message) {
        if (message === void 0) { message = HTTPErrorMessage.INTERNAL_SERVER_ERROR; }
        return _super.call(this, message, HTTPErrorStatus.INTERNAL_SERVER_ERROR) || this;
    }
    return InternalServerError;
}(HTTPError));
exports.InternalServerError = InternalServerError;
