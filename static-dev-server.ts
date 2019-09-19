import { createSecureServer, ServerHttp2Stream, IncomingHttpHeaders as Http2IncomingHttpHeaders } from 'http2';
import { RequestOptions, Agent, request, IncomingHttpHeaders } from 'http';
import * as fs from 'fs';
import { authenticateRequestViaNtlm } from './authentication';
import { serveStaticContent } from './serve-static';
import { toFirstThatOr, crash, asDefinedOr } from './utils';
import { ResponseHandler, readSettings } from './read-config';
import { CommandLineArguments } from './read-command-line';

// HACK: disable ssl certificate validation
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const server = createSecureServer({
    key: fs.readFileSync('localhost.key'),
    cert: fs.readFileSync('localhost.crt'),
});

export function startProxyServer(
    args: CommandLineArguments,
): void {
    const settings = readSettings(asDefinedOr(args.config, ''));

    console.log(`Starting proxy server on https://localhost:${settings.port} to ${settings.proxyProtocol}//${settings.proxyHost}:${settings.proxyPort}`);

    server.on('stream', (stream, headers) => {
        const reqPathWithQuery = asDefinedOr(headers[':path'], '/');
        const reqMethod = asDefinedOr(headers[':method'], 'GET');
        const [reqPath] = reqPathWithQuery.split('?');

        const proxySettings = toFirstThatOr(settings.proxy, value => value.path.test(reqPath), null);

        if (proxySettings !== null) { // authenticate and proxy request
            const options: RequestOptions = {
                protocol: settings.proxyProtocol,
                hostname: settings.proxyHost,
                port: settings.proxyPort,
                path: reqPathWithQuery,
                method: reqMethod,
                headers: filterRequestHeaders(headers),
                agent: new Agent({
                    keepAlive: true,
                    maxSockets: 1,
                    keepAliveMsecs: 3000,
                }),
            };
            return proxySettings.auth !== null && proxySettings.auth === 'ntlm'
                ? authAndProxyRequest(options, stream, proxySettings.responseHandler, args)
                : proxyRequest(options, stream, proxySettings.responseHandler);
        }

        return serveStaticContent(reqPath, settings.staticBase, stream);
    });

    server.listen(settings.port);
}

async function authAndProxyRequest(
    options: RequestOptions,
    stream: ServerHttp2Stream,
    handler: ResponseHandler | undefined,
    args: CommandLineArguments,
): Promise<void> {
    if (args.user === undefined || args.password === undefined) {
        return crash('Need to set user name and password for authenticate request.');
    }
    // options = _debug_(options); // pass request via proxy.
    await authenticateRequestViaNtlm(options, args.user, args.password);

    proxyRequest(options, stream, handler);
}

function proxyRequest(
    options: RequestOptions,
    stream: ServerHttp2Stream,
    handler: ResponseHandler | undefined,
): void {
    const proxied = request(options, async response => {        
        if (!stream.destroyed) {
            stream.respond(filterResponseHeaders(response.headers));
            response.on('end', () => destroyAgent(options));
            stream.on('aborted', () => {
                response.unpipe();
                proxied.abort();
                destroyAgent(options);
            });

            if (handler !== undefined) {
                await handler(response, stream);
            }
            else {
                response.pipe(stream, { end: true });
            }
        }
    });

    stream.pipe(proxied, { end: true });
    stream.on('end', () => proxied.end());
}

function destroyAgent(options: RequestOptions): void {
    if (options.agent !== undefined && options.agent instanceof Agent) {
        options.agent.destroy();
    }
}

function filterRequestHeaders(headers: Http2IncomingHttpHeaders): IncomingHttpHeaders {
    const result: IncomingHttpHeaders = {};
    for (const name in headers) {
        if (!name.startsWith(':') && name !== 'content-length') {
            result[name] = headers[name];
        }
    }
    return result;
}

function filterResponseHeaders(headers: IncomingHttpHeaders): typeof headers {
    const result: IncomingHttpHeaders = {};
    for (const name in headers) {
        if (name !== 'transfer-encoding' && name !== 'connection') {
            result[name] = headers[name];
        }
    }
    return result;
}
