"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ssoRouterUrl = void 0;
exports.ssoMiddleware = ssoMiddleware;
const https_1 = __importDefault(require("https"));
const express_1 = __importDefault(require("express"));
const querystring_1 = __importDefault(require("querystring"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const path_to_regexp_1 = require("path-to-regexp");
const ssoRouter = express_1.default.Router();
const tokenExpires = new Set();
function ssoMiddleware(options, routes = []) {
    let { active, app_id, login_url, callback_url, provider, secret } = options;
    if (active && (!app_id || !login_url || !callback_url || !provider)) {
        throw new Error("Both app_id, login_url, callback_url, provider are required for SSO middleware.");
    }
    if (active && provider === 'jwt' && !secret) {
        throw new Error("Secret is required for JWT provider.");
    }
    return function (req, res, next) {
        if (!active)
            return next();
        const isPathMatched = routes.some(routePath => {
            const matchPath = (0, path_to_regexp_1.match)(routePath, { decode: decodeURIComponent });
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
            }
            else if (req.xhr) {
                return res.status(401).json({ error: 'Unauthorized.' });
            }
            else {
                return res.redirect(login_url + '?' + querystring_1.default.stringify(params));
            }
        }
        else {
            let token = req.headers['x-access-token'] || req.headers['authorization'];
            if (token) {
                jsonwebtoken_1.default.verify(token, secret, (err, user) => {
                    if (err || tokenExpires.has(token)) {
                        return res.status(401).json({ error: 'Unauthorized.' });
                    }
                    req.user = user;
                    return next();
                });
            }
            else if (req.xhr) {
                return res.status(401).json({ error: 'Unauthorized.' });
            }
            else {
                return res.redirect(login_url + '?' + querystring_1.default.stringify(params));
            }
        }
    };
}
;
const ssoRouterUrl = (options) => {
    ssoRouter.get('/sso/callback', (req, res) => {
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
        }
        else {
            let postData = JSON.stringify({
                app_id: app_id,
                token: req.query.token,
                ip: req.ip,
                domain: req.get('host'),
                userAgent: req.get('User-Agent')
            });
            let request_url = new URL(auth_url);
            const request = https_1.default.request({
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
                                    res.redirect(redirect_url);
                                }
                                else {
                                    res.json(verify.user);
                                }
                            }
                            else { // jwt
                                token_options = token_options || { expiresIn: '24h' };
                                const token = jsonwebtoken_1.default.sign(verify.user, secret, token_options);
                                res.json({
                                    token: token,
                                    user: verify.user
                                });
                            }
                        }
                        else {
                            res.status(401).send("Unauthorized");
                        }
                    }
                    catch (error) {
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
    ssoRouter.get('/sso/logout', (req, res) => {
        let { active, app_id, logout_url, redirect_url, provider, secret } = options;
        if (!app_id || !logout_url || !redirect_url) {
            throw new Error("Both app_id, logout_url, redirect_url are required for SSO callback.");
        }
        provider = provider || 'session';
        if (!active) {
            res.status(406).send("SSO is disabled.");
        }
        else {
            if (provider === 'session') {
                if (req.session && req.session.user) {
                    delete req.session.user;
                }
            }
            else { // jwt
                let token = req.headers['x-access-token'] || req.headers['authorization'];
                if (token) {
                    jsonwebtoken_1.default.verify(token, secret, (err, user) => {
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
            res.redirect(logout_url + '?' + querystring_1.default.stringify(params));
        }
    });
    ssoRouter.get('/sso/reset-token', (req, res) => {
        tokenExpires.clear();
    });
    return ssoRouter;
};
exports.ssoRouterUrl = ssoRouterUrl;
exports.default = {
    ssoMiddleware,
    ssoRouterUrl: exports.ssoRouterUrl
};
