import { constants, ServerHttp2Stream } from 'http2';
import * as path from 'path';
import * as mime from 'mime-types';

const {
    HTTP_STATUS_NOT_FOUND,
    HTTP_STATUS_INTERNAL_SERVER_ERROR,
} = constants;

function respondErrorToStream(
    err: NodeJS.ErrnoException,
    stream: ServerHttp2Stream,
): void {
    console.log(err);
    if (err.code === 'ENOENT') {
        stream.respond({ ":status": HTTP_STATUS_NOT_FOUND });
    }
    else {
        stream.respond({ ":status": HTTP_STATUS_INTERNAL_SERVER_ERROR });
    }
    stream.end();
}

export function serveStaticContent(
    reqPath: string,
    contentBase: string,
    stream: ServerHttp2Stream,
): void {
    const fullPath = path.join(contentBase, reqPath);
    const responseMimeType = mime.lookup(fullPath);

    return stream.respondWithFile(
        fullPath,
        { 'content-type': responseMimeType as string },
        { onError: (err) => respondErrorToStream(err, stream) },
    );
}
