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
exports.ConflictError = exports.NotFoundError = exports.ForbiddenError = exports.UnauthorizedError = exports.BadRequestError = exports.ErrorStatus = exports.ErrorType = exports.HTTPError = void 0;
var HTTPError = /** @class */ (function (_super) {
    __extends(HTTPError, _super);
    function HTTPError(message, type, status) {
        var _this = _super.call(this, message) || this;
        _this.type = type;
        _this.status = status;
        return _this;
    }
    return HTTPError;
}(Error));
exports.HTTPError = HTTPError;
var ErrorType;
(function (ErrorType) {
    ErrorType["ERROR"] = "error";
    ErrorType["WARNING"] = "warning";
})(ErrorType = exports.ErrorType || (exports.ErrorType = {}));
var ErrorStatus;
(function (ErrorStatus) {
    ErrorStatus[ErrorStatus["BAD_REQUEST"] = 400] = "BAD_REQUEST";
    ErrorStatus[ErrorStatus["UNAUTHORIZED"] = 401] = "UNAUTHORIZED";
    ErrorStatus[ErrorStatus["FORBIDDEN"] = 403] = "FORBIDDEN";
    ErrorStatus[ErrorStatus["NOT_FOUND"] = 404] = "NOT_FOUND";
    ErrorStatus[ErrorStatus["CONFLICT"] = 409] = "CONFLICT";
})(ErrorStatus = exports.ErrorStatus || (exports.ErrorStatus = {}));
var BadRequestError = /** @class */ (function (_super) {
    __extends(BadRequestError, _super);
    function BadRequestError(message) {
        return _super.call(this, message, ErrorType.ERROR, ErrorStatus.BAD_REQUEST) || this;
    }
    return BadRequestError;
}(HTTPError));
exports.BadRequestError = BadRequestError;
var UnauthorizedError = /** @class */ (function (_super) {
    __extends(UnauthorizedError, _super);
    function UnauthorizedError(message) {
        return _super.call(this, message, ErrorType.ERROR, ErrorStatus.UNAUTHORIZED) || this;
    }
    return UnauthorizedError;
}(HTTPError));
exports.UnauthorizedError = UnauthorizedError;
var ForbiddenError = /** @class */ (function (_super) {
    __extends(ForbiddenError, _super);
    function ForbiddenError(message) {
        return _super.call(this, message, ErrorType.ERROR, ErrorStatus.FORBIDDEN) || this;
    }
    return ForbiddenError;
}(HTTPError));
exports.ForbiddenError = ForbiddenError;
var NotFoundError = /** @class */ (function (_super) {
    __extends(NotFoundError, _super);
    function NotFoundError(message) {
        return _super.call(this, message, ErrorType.ERROR, ErrorStatus.NOT_FOUND) || this;
    }
    return NotFoundError;
}(HTTPError));
exports.NotFoundError = NotFoundError;
var ConflictError = /** @class */ (function (_super) {
    __extends(ConflictError, _super);
    function ConflictError(message) {
        return _super.call(this, message, ErrorType.ERROR, ErrorStatus.CONFLICT) || this;
    }
    return ConflictError;
}(HTTPError));
exports.ConflictError = ConflictError;
