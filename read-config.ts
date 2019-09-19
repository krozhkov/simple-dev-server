import { IncomingMessage } from 'http';
import { ServerHttp2Stream } from 'http2';
import * as path from 'path';
import { URL } from 'url';
import { asDefinedOr, foldDict, appendToArray, insteadDefinedOr } from './utils';

export type ResponseHandler = (
    response: IncomingMessage,
    stream: ServerHttp2Stream,
) => Promise<void>;

export interface Config {
    readonly port?: number;
    readonly staticBase?: string;
    readonly proxyTo?: string;
    readonly proxy?: {
        [path: string]: {
            auth?: 'ntlm',
            responseHandler?: ResponseHandler,
        },
    },
}

interface ProxySettings {
    readonly path: RegExp;
    readonly auth: 'ntlm' | null;
    readonly responseHandler: ResponseHandler | undefined;
}

export interface Settings {
    readonly port: number;
    readonly staticBase: string;
    readonly proxyProtocol: string;
    readonly proxyHost: string;
    readonly proxyPort: number;
    readonly proxy: ProxySettings[];
}

function loadConfig(
    moduleName: string,
): Config {
    let config = {} as Config;

    try {
        config = require(moduleName);
    } catch (e) {
        config = {};
    }

    return config;
}

export function readSettings(
    moduleName: string,
): Settings {
    const config = loadConfig(moduleName);

    const port = asDefinedOr(config.port, 9000);
    const staticBase = path.join(__dirname, asDefinedOr(config.staticBase, './'));
    const proxyTo = insteadDefinedOr(config.proxyTo, url => new URL(url), null);

    const proxyProtocol = insteadDefinedOr(proxyTo, url => url.protocol, 'http:')
    const proxyHost = insteadDefinedOr(proxyTo, url => url.hostname, 'example.com');
    const proxyPort = insteadDefinedOr(proxyTo, url => parseInt(url.port), 80);

    const proxy = foldDict(
        asDefinedOr(config.proxy, {}),
        [] as ProxySettings[],
        (key, value, result) => appendToArray(
            result,
            {
                path: new RegExp(key),
                auth: asDefinedOr(value.auth, null),
                responseHandler: value.responseHandler,
            },
        ),
    );

    return {
        port,
        staticBase,
        proxyProtocol,
        proxyHost,
        proxyPort,
        proxy,
    };
}