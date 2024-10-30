import https from 'https';
import express from 'express';
import { Request, Response, NextFunction, RequestHandler } from "express";
import querystring from 'querystring';
import jwt from 'jsonwebtoken';
import { match } from 'path-to-regexp';

const ssoRouter = express.Router();
const tokenExpires = new Set();

declare global {
    namespace Express {
        interface Request {
            session?: {
                user?: {
                    [key: string]: any
                }
            };
            user?: {
                [key: string]: any
            }
        }
    }
}

export interface ssoOptions {
    active: boolean;
    provider: 'session' | 'jwt';
    token_options?: {
        [key: string]: any
    };
    secret?: any;
    app_id: number;
    login_url: string;
    logout_url: string;
    callback_url: string;
    auth_url: string;
    redirect_url?: string;
}

export function ssoMiddleware(options: ssoOptions, routes: Array<string> = []): RequestHandler {
    let { active, app_id, login_url, callback_url, provider, secret } = options;
    if (active && (!app_id || !login_url || !callback_url || !provider)) {
        throw new Error("Both app_id, login_url, callback_url, provider are required for SSO middleware.");
    }
    if (active && provider === 'jwt' && !secret) {
        throw new Error("Secret is required for JWT provider.");
    }
    
    return function (req: Request, res: Response, next: NextFunction) {
        if (!active) return next();
        
        const isPathMatched = routes.some(routePath => {
            const matchPath = match(routePath, { decode: decodeURIComponent });
            return matchPath(req.path);
        });
        if (!isPathMatched) {
            if (provider === 'session' && req.session && req.session.user) {
                req.user = req.session.user;
            }
            return next();
        } 

        let params = {
            app_id: app_id,
            continue: callback_url
        };
        if (provider === 'session') {
            if (req.session && req.session.user) {
                req.user = req.session.user;
                return next();
            } else if (req.xhr) {
                return res.status(401).json({ error: 'Unauthorized.' });
            } else {
                return res.redirect(login_url + '?' + querystring.stringify(params));
            }
        } else {
            let token: any = req.headers['x-access-token'] || req.headers['authorization'];
            if (token) {
                jwt.verify(token, secret, (err: any, user: any) => {
                    if (err || tokenExpires.has(token)) {
                        return res.status(401).json({ error: 'Unauthorized.' });
                    }

                    req.user = user;
                    return next();
                });
            } else if (req.xhr) {
                return res.status(401).json({ error: 'Unauthorized.' });
            } else {
                return res.redirect(login_url + '?' + querystring.stringify(params));
            }
        }
    } as RequestHandler;
};

export const ssoRouterUrl = (options: ssoOptions) => {
    ssoRouter.get('/sso/callback', (req: Request, res: Response) => {
        let { active, app_id, redirect_url, auth_url, provider, secret, token_options } = options;
        if (!app_id || !auth_url) {
            throw new Error("Both app_id, auth_url are required for SSO callback.");
        }
        provider = provider || 'session';
        if (provider === 'jwt' && !secret) {
            throw new Error("Secret is required for JWT provider.");
        }

        if (!active) {
            res.status(406).send("SSO is disabled.");
        } else {
            let postData = JSON.stringify({
                app_id: app_id,
                token: req.query.token,
                ip: req.ip,
                domain: req.get('host'),
                userAgent: req.get('User-Agent')
            });
            let request_url = new URL(auth_url);
            const request = https.request({
                hostname: request_url.hostname,
                port: request_url.port || 443,
                path: request_url.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData),
                }
            }, (response) => {
                let data = '';
                response.on('data', (chunk) => {
                    data += chunk;
                });
                response.on('end', () => {
                    try {
                        const verify = JSON.parse(data);
                        if (verify.status === 'success' && verify.user) {
                            if (provider === 'session') {
                                if (req.session) {
                                    req.session.user = verify.user;
                                }
                                if (redirect_url) {
                                    res.redirect(redirect_url)
                                } else {
                                    res.json(verify.user)
                                }
                            } else { // jwt
                                token_options = token_options || { expiresIn: '24h' };
                                const token = jwt.sign(verify.user, secret, token_options);
                                res.json({ 
                                    token: token, 
                                    user: verify.user 
                                });
                            }
                        } else {
                            res.status(401).send("Unauthorized");
                        }
                    } catch (error) {
                        console.error("Error parsing response:", error);
                        res.status(500).send("An error occurred during token verification.");
                    }
                });
            });

            request.on('error', (error) => {
                console.error("Request error verify SSO:", error);
                res.status(500).send("An error occurred while verifying the token.");
            });

            request.write(postData);
            request.end();
        }
    });

    ssoRouter.get('/sso/logout', (req: Request, res: Response) => {
        let { active, app_id, logout_url, redirect_url, provider, secret } = options;
        if (!app_id || !logout_url || !redirect_url) {
            throw new Error("Both app_id, logout_url, redirect_url are required for SSO callback.");
        }
        provider = provider || 'session';
        if (!active) {
            res.status(406).send("SSO is disabled.");
        } else {
            if (provider === 'session') {
                if (req.session && req.session.user) {
                    delete req.session.user;
                }
            } else { // jwt
                let token: any = req.headers['x-access-token'] || req.headers['authorization'];
                if (token) {
                    jwt.verify(token, secret, (err: any, user: any) => {
                        if (!err && !tokenExpires.has(token)) {
                            tokenExpires.add(token);
                        }
                    });
                }
            }
            let params = {
                app_id: app_id,
                continue: redirect_url
            };
            res.redirect(logout_url + '?' + querystring.stringify(params));
        }
    });

    ssoRouter.get('/sso/reset-token', (req: Request, res: Response) => {
        tokenExpires.clear();
    });

    return ssoRouter;
};

export default {
    ssoMiddleware,
    ssoRouterUrl
};