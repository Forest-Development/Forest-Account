"use strict";
exports.__esModule = true;
var client_1 = require("@prisma/client");
var prisma = new client_1.PrismaClient();
var scopes = [
    { name: "FULL_ACCESS", description: "Full access" }
];
prisma.scope.createMany({
    data: scopes,
    skipDuplicates: true
}).then(function (result) {
    console.log(result);
})["catch"](function (error) {
    console.log(error);
})["finally"](function () {
    prisma.$disconnect();
});
