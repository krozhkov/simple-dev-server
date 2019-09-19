import { IncomingMessage } from 'http';
import { ServerHttp2Stream } from 'http2';
import { willReadStreamAsString } from './utils';
import { Config } from './read-config';

const config: Config = {
    port: 45443,
    staticBase: '../../APS2/src/Intelsat.APS.Web',
    proxyTo: 'http://localhost:57465/',
    proxy: {
        '^/$': { auth: 'ntlm' },
        '^/api/': { auth: 'ntlm' },
        '^/signalr/negotiate': {
            auth: 'ntlm',
            responseHandler: handleSignalrNegotiateResponse,
        },
        '^/signalr/': { auth: 'ntlm' },
    },
};

export = config;

async function handleSignalrNegotiateResponse(
    response: IncomingMessage,
    stream: ServerHttp2Stream,
): Promise<void> {
    const data = JSON.parse(await willReadStreamAsString(response));
    // disable use WebSocket for SignalR.
    data.TryWebSockets = false;
    stream.end(JSON.stringify(data));
}
