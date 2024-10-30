import { RequestHandler } from "express";
declare global {
    namespace Express {
        interface Request {
            session?: {
                user?: {
                    [key: string]: any;
                };
            };
            user?: {
                [key: string]: any;
            };
        }
    }
}
export interface ssoOptions {
    active: boolean;
    provider: 'session' | 'jwt';
    token_options?: {
        [key: string]: any;
    };
    secret?: any;
    app_id: number;
    login_url: string;
    logout_url: string;
    callback_url: string;
    auth_url: string;
    redirect_url?: string;
}
export declare function ssoMiddleware(options: ssoOptions, routes?: Array<string>): RequestHandler;
export declare const ssoRouterUrl: (options: ssoOptions) => import("express-serve-static-core").Router;
declare const _default: {
    ssoMiddleware: typeof ssoMiddleware;
    ssoRouterUrl: (options: ssoOptions) => import("express-serve-static-core").Router;
};
export default _default;
