"use strict";
exports.__esModule = true;
exports.MailBuilder = void 0;
var nodemailer = require('nodemailer');
var MailBuilder = /** @class */ (function () {
    function MailBuilder() {
        this.transporterOptions = {
            service: 'gmail',
            auth: {
                user: 'jalabendowicz@gmail.com',
                pass: 'hamlwpkedolrwfax'
            }
        };
        this.mailOptions = {
            from: 'jalabendowicz@gmail.com',
            to: '',
            subject: '',
            text: ''
        };
    }
    MailBuilder.prototype.withRecipient = function (recipient) {
        this.mailOptions.to = recipient;
        return this;
    };
    MailBuilder.prototype.withSubject = function (subject) {
        this.mailOptions.subject = subject;
        return this;
    };
    MailBuilder.prototype.withText = function (text) {
        this.mailOptions.text = text;
        return this;
    };
    MailBuilder.prototype.withHtml = function (html) {
        this.mailOptions.html = html;
        return this;
    };
    MailBuilder.prototype.send = function () {
        nodemailer.createTransport(this.transporterOptions).sendMail(this.mailOptions);
    };
    return MailBuilder;
}());
exports.MailBuilder = MailBuilder;
