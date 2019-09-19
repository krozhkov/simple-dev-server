import * as crypto from 'crypto';
import * as os from 'os';
import { crash } from './utils';

enum NTLMFLAG {
    /* Indicates that Unicode strings are supported for use in security buffer data. */
    NEGOTIATE_UNICODE = 1 << 0,
    /* Indicates that OEM strings are supported for use in security buffer data. */
    NEGOTIATE_OEM = 1 << 1,
    /* Requests that the server's authentication realm be included in the Type 2 message. */
    REQUEST_TARGET = 1 << 2,
    /* Indicates that NTLM authentication is being used. */
    NEGOTIATE_NTLM_KEY = 1 << 9,
    /* Indicates that authenticated communication between the client and server
       should be signed with a "dummy" signature. */
    NEGOTIATE_ALWAYS_SIGN = 1 << 15,
    /* Indicates that the NTLM2 signing and sealing scheme should be used for
       protecting authenticated communications. */
    NEGOTIATE_NTLM2_KEY = 1 << 19,
    /* Sent by the server in the Type 2 message to indicate that it is including a
       Target Information block in the message. */
    NEGOTIATE_TARGET_INFO = 1 << 23
}

interface ChallengeMessage {
    readonly flags: NTLMFLAG;
    readonly version: number;
    readonly encoding: string;
    readonly challenge: Buffer;
    readonly targetName: string;
    readonly targetInfo: Buffer;
}

function createNTLMHash(password: string): Buffer {
    const md4sum = crypto.createHash('md4');
    md4sum.update(Buffer.from(password, 'ucs2'));
    return md4sum.digest();
}

function createNTLMv2Hash(ntlmhash: Buffer, username: string, authTargetName: string): Buffer {
    const hmac = crypto.createHmac('md5', ntlmhash);
    hmac.update(Buffer.from(username.toUpperCase() + authTargetName, 'ucs2'));
    return hmac.digest();
}

function createHmacMd5(ntlm2hash: Buffer, buffer: Buffer): Buffer {
    const hmac = crypto.createHmac('md5', ntlm2hash);
    return hmac.update(buffer).digest();
}

function createPseudoRandomValue(length: number): string {
    return new Array(length).fill(undefined)
        .map(() => Math.floor(Math.random() * 16).toString(16))
        .join('');
}

function createLMv2Response(
    challengeMessage: ChallengeMessage,
    username: string,
    ntlmhash: Buffer,
    nonce: string,
): Buffer {
    const buffer = Buffer.alloc(24);
    const ntlm2hash = createNTLMv2Hash(ntlmhash, username, challengeMessage.targetName);

    //server challenge
    challengeMessage.challenge.copy(buffer, 8);
    //client nonce
    buffer.write(nonce, 16, nonce.length / 2, 'hex');
    //create hash
    const hashedBuffer = createHmacMd5(ntlm2hash, buffer.slice(8));
    hashedBuffer.copy(buffer);

    return buffer;
}

function ntmlNow(): [number, number] {
    // we are loosing precision here since js is not able to handle those large integers
    // 11644473600000 = diff between 1970 and 1601
    const timestamp = ((Date.now() + 11644473600000) * 10000).toString(16);
    const timestampLow = parseInt(timestamp.substring(Math.max(0, timestamp.length - 8)), 16);
    const timestampHigh = parseInt(timestamp.substring(0, Math.max(0, timestamp.length - 8)), 16);
    return [timestampLow, timestampHigh];
}

function createNTLMv2Response(
    challengeMessage: ChallengeMessage,
    username: string,
    ntlmhash: Buffer,
    nonce: string,
): Buffer {
    const buffer = Buffer.alloc(48 + challengeMessage.targetInfo.length);
    const ntlm2hash = createNTLMv2Hash(ntlmhash, username, challengeMessage.targetName);

    // the first 8 bytes are spare to store the hashed value before the blob
    // server challenge
    challengeMessage.challenge.copy(buffer, 8);

    // blob signature
    buffer.writeUInt32BE(0x01010000, 16);

    // reserved
    buffer.writeUInt32LE(0, 20);

    const [timestampLow, timestampHigh] = ntmlNow();
    buffer.writeUInt32LE(timestampLow, 24);
    buffer.writeUInt32LE(timestampHigh, 28);

    // random client nonce
    buffer.write(nonce, 32, nonce.length / 2, 'hex');

    // zero
    buffer.writeUInt32LE(0, 40);

    // complete target information block from type 2 message
    challengeMessage.targetInfo.copy(buffer, 44);

    // zero
    buffer.writeUInt32LE(0, 44 + challengeMessage.targetInfo.length);

    const hashedBuffer = createHmacMd5(ntlm2hash, buffer.slice(8));
    hashedBuffer.copy(buffer);

    return buffer;
}

const NTLMSIGNATURE = 'NTLMSSP\0';
const NTLMPREFIX = 'NTLM ';
const negotiateMessageType = 1;
const challengeMessageType = 2;
const authenticateMessageType = 3;

export function createNegotiateMessage(
    workstation: string = os.hostname(),
    domainName = '',
): string {
    // Create a large enough buffer
    const buffer = Buffer.alloc(1024);
    // Signature
    let dataPosition = 32; // Payload offset
    let position = buffer.write(NTLMSIGNATURE, 0, NTLMSIGNATURE.length, 'ascii');
    // Message type (must be set to 0x00000001)
    position = buffer.writeUInt32LE(negotiateMessageType, position);
    // Negotiate flags
    position = buffer.writeUInt32LE(
        NTLMFLAG.NEGOTIATE_OEM
        | NTLMFLAG.REQUEST_TARGET
        | NTLMFLAG.NEGOTIATE_NTLM_KEY
        | NTLMFLAG.NEGOTIATE_NTLM2_KEY
        | NTLMFLAG.NEGOTIATE_ALWAYS_SIGN,
        position,
    );
    // Domain security buffer
    const domainNameLen = domainName.length;
    position = buffer.writeUInt16LE(domainNameLen, position); // DomainNameLen
    position = buffer.writeUInt16LE(domainNameLen, position); // DomainNameMaxLen
    position = buffer.writeUInt32LE(domainNameLen === 0 ? 0 : dataPosition, position);

    dataPosition += domainNameLen > 0
        ? buffer.write(domainName, dataPosition, domainNameLen, 'ascii') : 0;

    // Workstation security buffer
    position = buffer.writeUInt16LE(workstation.length, position); // WorkstationLen
    position = buffer.writeUInt16LE(workstation.length, position); // WorkstationMaxLen
    position = buffer.writeUInt32LE(workstation.length === 0 ? 0 : dataPosition, position);

    dataPosition += workstation.length > 0
        ? buffer.write(workstation, dataPosition, workstation.length, 'ascii') : 0;

    return NTLMPREFIX + buffer.toString('base64', 0, dataPosition);
}

function targetNameOutOfChallengeMessage(buffer: Buffer, encoding: string): string {
    const length = buffer.readUInt16LE(12); // TargetNameLen
    // skipping allocated space
    const offset = buffer.readUInt32LE(16); // TargetNameBufferOffset

    return length !== 0 && (offset + length) < buffer.length && offset >= 32
        ? buffer.toString(encoding, offset, offset + length) : '';
}

function targetInfoOutOfChallengeMessage(buffer: Buffer): Buffer {
    const length = buffer.readUInt16LE(40);
    // skipping allocated space
    const offset = buffer.readUInt32LE(44);

    return buffer.slice(offset, offset + length);
}

export function parseChallengeMessage(response: string): ChallengeMessage {
    response = response.startsWith(NTLMPREFIX)
        ? response.slice(NTLMPREFIX.length) : response;

    const buffer = Buffer.from(response, 'base64');

    // check signature
    const signature = buffer.toString('ascii', 0, NTLMSIGNATURE.length);
    if (signature !== NTLMSIGNATURE) {
        console.warn(response);
        return crash('Invalid message signature: ' + signature);
    }

    // check message type
    // This field MUST be set to 0x00000002.
    if (buffer.readUInt32LE(NTLMSIGNATURE.length) !== challengeMessageType) {
        return crash('Invalid message type');
    }

    // read flags
    const flags = buffer.readUInt32LE(20) as NTLMFLAG;

    const encoding = (flags & NTLMFLAG.NEGOTIATE_OEM) ? 'ascii' : 'ucs2';

    const version = (flags & NTLMFLAG.NEGOTIATE_NTLM2_KEY) ? 2 : 1;

    const challenge = buffer.slice(24, 32);

    // read target name
    const targetName = targetNameOutOfChallengeMessage(buffer, encoding);

    // read target info
    const targetInfo = flags & NTLMFLAG.NEGOTIATE_TARGET_INFO
        ? targetInfoOutOfChallengeMessage(buffer)
        : Buffer.alloc(0);

    return {
        flags,
        encoding,
        version,
        challenge,
        targetName,
        targetInfo,
    };
}

export function createAuthenticateMessage(
    challengeMessage: ChallengeMessage,
    username: string,
    password: string,
    workstation: string = os.hostname(),
    target: string = challengeMessage.targetName,
): string {
    if (challengeMessage.version !== 2) {
        return crash('Only version 2 protocol is supported.');
    }

    const buffer = Buffer.alloc(1024);
    const { flags } = challengeMessage;
    const encoding = challengeMessage.encoding as BufferEncoding;
    const bytesPerSymbol = encoding === 'ascii' ? 1 : 2;
    let dataPosition = 64;

    // signature
    let position = buffer.write(NTLMSIGNATURE, 0, NTLMSIGNATURE.length, 'ascii');
    // message type
    position = buffer.writeUInt32LE(authenticateMessageType, position);

    const ntlmHash = createNTLMHash(password);
    const nonce = createPseudoRandomValue(16);
    const lmv2 = createLMv2Response(challengeMessage, username, ntlmHash, nonce);
    const ntlmv2 = createNTLMv2Response(challengeMessage, username, ntlmHash, nonce);

    // lmv2 security buffer
    position = buffer.writeUInt16LE(lmv2.length, position);
    position = buffer.writeUInt16LE(lmv2.length, position);
    position = buffer.writeUInt32LE(dataPosition, position);
    dataPosition += lmv2.copy(buffer, dataPosition);

    // ntlmv2 security buffer
    position = buffer.writeUInt16LE(ntlmv2.length, position);
    position = buffer.writeUInt16LE(ntlmv2.length, position);
    position = buffer.writeUInt32LE(dataPosition, position);
    dataPosition += ntlmv2.copy(buffer, dataPosition);

    // target name security buffer
    position = buffer.writeUInt16LE(target.length * bytesPerSymbol, position);
    position = buffer.writeUInt16LE(target.length * bytesPerSymbol, position);
    position = buffer.writeUInt32LE(dataPosition, position);
    dataPosition += buffer.write(target, dataPosition, target.length * bytesPerSymbol, encoding);

    // user name security buffer
    position = buffer.writeUInt16LE(username.length * bytesPerSymbol, position);
    position = buffer.writeUInt16LE(username.length * bytesPerSymbol, position);
    position = buffer.writeUInt32LE(dataPosition, position);
    dataPosition += buffer.write(username, dataPosition, username.length * bytesPerSymbol, encoding);

    // workstation name security buffer
    position = buffer.writeUInt16LE(workstation.length * bytesPerSymbol, position);
    position = buffer.writeUInt16LE(workstation.length * bytesPerSymbol, position);
    position = buffer.writeUInt32LE(dataPosition, position);
    dataPosition += buffer.write(workstation, dataPosition, workstation.length * bytesPerSymbol, encoding);

    // session key security buffer
    position = buffer.writeUInt16LE(0, position);
    position = buffer.writeUInt16LE(0, position);
    position = buffer.writeUInt32LE(0, position);

    // flags
    position = buffer.writeUInt32LE(flags, position);

    return NTLMPREFIX + buffer.toString('base64', 0, dataPosition);
}
