"use strict";
exports.__esModule = true;
var client_1 = require("@prisma/client");
var prisma = new client_1.PrismaClient();
var roles = [
    { name: "ADMINISTRATOR", description: "Administrator" },
    { name: "PERMISSIONS_DIRECTOR", description: "Permissions director" },
    { name: "ROLES_DIRECTOR", description: "Roles director" },
    { name: "SCOPES_DIRECTOR", description: "Scopes director" },
    { name: "USERS_DIRECTOR", description: "Users director" },
    { name: "CLIENTS_DIRECTOR", description: "Clients director" },
    { name: "USER", description: "User" }
];
prisma.role.createMany({
    data: roles,
    skipDuplicates: true
}).then(function (result) {
    console.log(result);
})["catch"](function (error) {
    console.log(error);
})["finally"](function () {
    prisma.$disconnect();
});
