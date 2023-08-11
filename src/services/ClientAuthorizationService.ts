import express, { Request, Response, NextFunction, Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { HTTPResponseBody, HTTPResponseBodyResult } from '../types/HTTPResponse';
import { HTTPSuccessType, HTTPSuccessMessage, HTTPSuccessStatus } from '../types/HTTPSuccess';
import { HTTPErrorType, HTTPErrorMessage, HTTPErrorStatus, HTTPError, BadRequestError, UnauthorizedError, ForbiddenError, NotFoundError, ConflictError, InternalServerError } from '../types/HTTPError';
import jwt, {Secret} from 'jsonwebtoken';
import { UserEmailNotificationBuilder } from '../builders/UserEmailNotificationBuilder';
const prisma = new PrismaClient();

export const authorizeClient = async (req: Request, res: Response, next:NextFunction) => {
    try {
        const client = await prisma.client.findUnique({
            where: {
              id: req.body.data.clientId
            },
            include: {
                clientScopes: {
                    include: {
                        scope: true
                    }
                },
                clientAllowedScopes: {
                    include: {
                        scope: true
                    }
                },
            }
        });
        if (!client) {
            throw new NotFoundError("Client not found");
            }
        if (client.active === false) {
            throw new ForbiddenError("Client already deactivated")
        }
        let clientRequestedScopes:string[] = req.body.data.scopes;
        let clientScopes:string[] = [];
        let clientAllowedScopes:string[] = [];
        let clientNotAllowedScopesToAllow:string[] = [];
        client.clientScopes.forEach((clientScope) => {
            clientScopes.push(clientScope.scope.name);
        });
        client.clientAllowedScopes.forEach((clientAllowedScope) => {
            clientAllowedScopes.push(clientAllowedScope.scope.name);
        });
        clientRequestedScopes.forEach((clientRequestedScope) => {
            if (clientScopes.includes(clientRequestedScope)) {
                if (!clientAllowedScopes.includes(clientRequestedScope)) {
                    clientNotAllowedScopesToAllow.push(clientRequestedScope);
                }
            } else {
                throw new BadRequestError("Client requested scope not allowed");
            }
        });
        if (clientNotAllowedScopesToAllow.length > 0) {
            const createdClientAllowedScopes = await prisma.clientAllowedScope.createMany({
                data: clientNotAllowedScopesToAllow.map((clientNotAllowedScope) => {
                    return {
                        clientId: client.id,
                        scopeId: (client.clientScopes.find((clientScope) => clientScope.scope.name === clientNotAllowedScope)?.scopeId as string),
                        userId: req.body.middlewareData.token.userId
                    }
                })
            });
        }

        let findedClientAllowedScopes = await prisma.clientAllowedScope.findMany({
            where: {
                clientId: client.id
            },
            include: {
                scope: true
            }
        });
        let clientAllowedScopeNames:string[] = [];
        findedClientAllowedScopes.forEach((findedClientAllowedScope) => {
            clientAllowedScopeNames.push(findedClientAllowedScope.scope.name);
        });
        let user = await prisma.user.findUnique({
            where: {
                id: req.body.middlewareData.token.userId
            }
        });

        new UserEmailNotificationBuilder()
        .withUserId(req.body.middlewareData.token.userId)
        .withSubject("Client authorized")
        .withTemplate("ClientAuthorized")
        .withContext({
            firstName: (user as any).firstName,
            clientAllowedScopes: clientAllowedScopeNames
        })
        .send();

        const tokenSecret: Secret = process.env.TOKEN_SECRET as Secret;
        if(req.body.data.response_type === "code") {
            const clientAuthorizationCode = await prisma.clientAuthorizationCode.create({
                data: {
                    userId: req.body.middlewareData.token.userId,
                    clientId: client.id,
                    code: jwt.sign({userId: req.body.middlewareData.token.userId, clientId: client.id, tokenType: "CLIENT_AUTHORIZATION_CODE"}, tokenSecret, {expiresIn: '1m'}),
                    expiresAt: new Date(Date.now() + 60000)
                },
            });
            let responseBodyResult = new HTTPResponseBodyResult(HTTPSuccessMessage.RECORD_CREATED, HTTPSuccessType, HTTPSuccessStatus.OK, req.originalUrl);
            let responseBody = new HTTPResponseBody(clientAuthorizationCode, responseBodyResult);
            res.status(201).json(responseBody);
        } else if (req.body.data.response_type === "token") {
            if (client.secret !== req.body.data.clientSecret) {
                throw new UnauthorizedError("Invalid client secret");
            }
            const clientRefreshToken = await prisma.clientRefreshToken.create({
                data: {
                    userId: req.body.middlewareData.token.userId,
                    clientId: client.id,
                    token: jwt.sign({
                        userId: req.body.middlewareData.token.userId,
                        clientId: client.id, 
                        tokenType: "CLIENT_REFRESH_TOKEN"
                    }, tokenSecret, {expiresIn: '7d'}),
                    expiresAt: new Date(Date.now() + 604800000)
                },
            });
            const clientAccessToken = await prisma.clientAccessToken.create({
                data: {
                    userId: req.body.middlewareData.token.userId,
                    clientId: client.id,
                    token: jwt.sign({
                        userId: req.body.middlewareData.token.userId,
                        clientId: client.id,
                        tokenType: "CLIENT_ACCESS_TOKEN"
                    }, tokenSecret, {expiresIn: '1d'}),
                    expiresAt: new Date(Date.now() + 86400000),
                    clientRefreshTokenId: clientRefreshToken.id
                },
            });
            let responseBodyResult = new HTTPResponseBodyResult(HTTPSuccessMessage.RECORD_CREATED, HTTPSuccessType, HTTPSuccessStatus.OK, req.originalUrl);
            let responseBody = new HTTPResponseBody({clientRefreshToken: clientRefreshToken, clientAccessToken: clientAccessToken}, responseBodyResult);
            res.status(201).json(responseBody);
        } else {
            throw new BadRequestError("Invalid response type");
        }
    } catch (error) {
        next(error as HTTPError);
    }
}

export const exchangeClientToken = async (req: Request, res: Response, next:NextFunction) => {
    try {
        const client = await prisma.client.findUnique({
            where: {
              id: req.body.data.clientId,
              secret: req.body.data.clientSecret
            }
        });
        if (!client) {
            throw new NotFoundError("Client not found");
            }
        if (client.active === false) {
            throw new ForbiddenError("Client already deactivated")
        }
        const clientAuthorizationCode = await prisma.clientAuthorizationCode.findUnique({
            where: {
                code: req.body.data.code
            },
            include: {
                user: true
            }
        });
        if (!clientAuthorizationCode) {
            throw new NotFoundError("Authorization code not found");
        }
        if (clientAuthorizationCode.clientId !== client.id) {
            throw new UnauthorizedError("Client not authorized");
        }
        if (clientAuthorizationCode.active === false) {
            throw new UnauthorizedError("Authorization code already used");
        }
        const tokenSecret: Secret = process.env.TOKEN_SECRET as Secret;
        const clientRefreshToken = await prisma.clientRefreshToken.create({
            data: {
                userId: clientAuthorizationCode.userId,
                clientId: client.id,
                token: jwt.sign({
                    userId: clientAuthorizationCode.userId,
                    clientId: client.id, 
                    tokenType: "CLIENT_REFRESH_TOKEN"
                }, tokenSecret, {expiresIn: '7d'}),
                expiresAt: new Date(Date.now() + 604800000),
                clientAuthorizationCodeId: clientAuthorizationCode.id
            },
        });
        const clientAccessToken = await prisma.clientAccessToken.create({
            data: {
                userId: clientAuthorizationCode.userId,
                clientId: client.id,
                token: jwt.sign({
                    userId: clientAuthorizationCode.userId,
                    clientId: client.id,
                    tokenType: "CLIENT_ACCESS_TOKEN"
                }, tokenSecret, {expiresIn: '1d'}),
                expiresAt: new Date(Date.now() + 86400000),
                clientRefreshTokenId: clientRefreshToken.id,
                clientAuthorizationCodeId: clientAuthorizationCode.id
            },
        });
        await prisma.clientAuthorizationCode.update({
            where: {
                id: clientAuthorizationCode.id
            },
            data: {
                active: false
            }
        });
        let responseBodyResult = new HTTPResponseBodyResult(HTTPSuccessMessage.RECORD_CREATED, HTTPSuccessType, HTTPSuccessStatus.OK, req.originalUrl);
        let responseBody = new HTTPResponseBody({clientRefreshToken: clientRefreshToken, clientAccessToken: clientAccessToken}, responseBodyResult);
        res.status(201).json(responseBody);
    } catch (error) {
        next(error as HTTPError);
    }
}

export const refreshClientToken = async (req: Request, res: Response, next:NextFunction) => {
    try {
        let record;
        const tokenSecret: Secret = process.env.TOKEN_SECRET as Secret;
        if (req.body.middlewareData.token.tokenType === "CLIENT_REFRESH_TOKEN") {
            record = await prisma.clientAccessToken.create({
                data: {
                    userId: req.body.middlewareData.token.userId,
                    clientId: req.body.middlewareData.token.clientId,
                    token: jwt.sign({
                        userId: req.body.middlewareData.token.userId,
                        clientId: req.body.middlewareData.token.clientId,
                        tokenType: "CLIENT_ACCESS_TOKEN"
                    }, tokenSecret, {expiresIn: '1d'}),
                    expiresAt: new Date(Date.now() + 600000),
                    clientRefreshTokenId: req.body.middlewareData.token.id,
                    clientAuthorizationCodeId: req.body.middlewareData.token.clientAuthorizationCodeId
                },
            });
        } else {
            throw new BadRequestError("Invalid token type");
        }
        let responseBodyResult = new HTTPResponseBodyResult(HTTPSuccessMessage.RECORD_CREATED, HTTPSuccessType, HTTPSuccessStatus.OK, req.originalUrl);
        let responseBody = new HTTPResponseBody(record, responseBodyResult);
        res.status(201).json(responseBody);
    } catch (error) {
        next(error as HTTPError);
    }
}

export const findClientToken = async (req: Request, res: Response, next:NextFunction) => {
    try {
        let record;
        if(req.body.middlewareData.token.tokenType === "CLIENT_ACCESS_TOKEN") {
            record = await prisma.clientAccessToken.findUnique({
                where: {
                token: req.body.middlewareData.token.token,
                },
            });
        } else if (req.body.middlewareData.token.tokenType === "CLIENT_REFRESH_TOKEN") {
            record = await prisma.clientRefreshToken.findUnique({
                where: {
                token: req.body.middlewareData.token.token,
                },
            });
        } else {
            throw new BadRequestError("Invalid token type");
        }
        let responseBodyResult = new HTTPResponseBodyResult(HTTPSuccessMessage.RECORD_FOUND, HTTPSuccessType, HTTPSuccessStatus.OK, req.originalUrl);
        let responseBody = new HTTPResponseBody(record, responseBodyResult);
        res.status(201).json(responseBody);
    } catch (error) {
        next(error as HTTPError);
    }
}

export const deactivateClientToken = async (req: Request, res: Response, next:NextFunction) => {
    try {
        let record;
        if (req.body.middlewareData.token.tokenType === "CLIENT_ACCESS_TOKEN") {
            record = await prisma.clientAccessToken.update({
                where: { id: req.body.middlewareData.token.id },
                data: { active: false },
            });
        } else if (req.body.middlewareData.token.tokenType === "CLIENT_REFRESH_TOKEN") {
            record = await prisma.clientRefreshToken.update({
                where: { id: req.body.middlewareData.token.id },
                data: { active: false },
            });
        } else {
            throw new BadRequestError("Invalid token type");
        }
        let responseBodyResult = new HTTPResponseBodyResult(HTTPSuccessMessage.RECORD_DEACTIVATED, HTTPSuccessType, HTTPSuccessStatus.OK, req.originalUrl);
        let responseBody = new HTTPResponseBody(record, responseBodyResult);
        res.status(201).json(responseBody);
    } catch (error) {
        next(error as HTTPError);
    }
}