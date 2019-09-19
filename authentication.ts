import { RequestOptions, request } from 'http';
import { createNegotiateMessage, parseChallengeMessage, createAuthenticateMessage } from './ntlm-auth';
import { crash } from './utils';

export function authenticateRequestViaNtlm(
    options: RequestOptions,
    user: string,
    password: string,
): Promise<void> {
    return new Promise<void>((resolve, _reject) => {
        _authenticateRequestViaNtlm(options, user, password, resolve);
    });
}

function _authenticateRequestViaNtlm(
    options: RequestOptions,
    user: string,
    password: string,
    resolve: () => void,
): void {
    Object.assign(options.headers, { Authorization: createNegotiateMessage() });
    request(options, response => {
        response.resume();
        const authenticateHeader = response.headers['www-authenticate'];
        if (true
            && authenticateHeader !== undefined
            && (authenticateHeader === 'Negotiate, NTLM' || authenticateHeader === 'NTLM')
        ) {
            // receive NTLM handshake
            return _authenticateRequestViaNtlm(options, user, password, resolve);
        }

        if (authenticateHeader === undefined) return crash('WWW-Authenticate header must be defined.');

        const decoded = parseChallengeMessage(authenticateHeader);

        options.headers = options.headers || {};
        options.headers.Authorization = createAuthenticateMessage(decoded, user, password);
        return resolve();
    }).end();
}
