import { Readable } from 'stream';
import { RequestOptions } from 'http';

export function crash(message: string): never {
    throw new Error(message);
}

export function asDefinedOr<T, O>(
    value: T | undefined | null,
    otherwise: O,
): T | O {
    return value !== undefined && value !== null
        ? value
        : otherwise;
}

export function insteadDefinedOr<T, U, O>(
    value: T | undefined | null,
    instead: (value: T) => U,
    otherwise: O,
): U | O {
    return value !== undefined && value !== null
        ? instead(value)
        : otherwise;
}

export function foldDict<T, R>(
    dict: { [key: string]: T },
    result: R,
    fold: (key: string, value: T, result: R) => R,
): R {
    for (const key in dict) {
        const value = dict[key];
        result = fold(key, value, result);
    }

    return result;
}

export function appendToArray<T>(values: T[], value: T): T[] {
    values.push(value);
    return values;
}

export function toFirstThatOr<T, O>(
    values: T[],
    isThat: (value: T) => boolean,
    or: O,
): T | O {
    const found = values.find(isThat);
    return asDefinedOr(found, or);
}

export function valueAt<T>(values: T[], position: number): T | undefined {
    return position >= 0 && position < values.length
        ? values[position]
        : undefined;
}

export function willReadStreamAsString(message: Readable): Promise<string> {
    return new Promise<string>((resolve, reject) => {
        const chunks: string[] = [];
        message.on('data', (chunk: string) => {
            chunks.push(chunk);
        });
        message.on('end', () => {
            const text = chunks.join('');
            resolve(text);
        });
        message.on('error', error => {
            reject(error);
        });
    });
}

export function _debug_(options: RequestOptions): typeof options {
    options = Object.assign({}, options);
    options.path = `${options.protocol}//${options.hostname}:${options.port}${options.path}`;
    options.headers = options.headers || {};
    options.headers.Host = `${options.hostname}:${options.port}`;
    options.protocol = 'http:';
    options.hostname = '127.0.0.1';
    options.port = 8888;
    options.host = undefined;
    return options;
};
