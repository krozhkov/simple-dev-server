import { readCommandLine } from './read-command-line';
import { startProxyServer } from './static-dev-server';

const argv = process.argv.slice(2);
const args = readCommandLine(argv);

process.on('uncaughtException', function (err) {
    // HACK: dirty fix for broken connection.
    if (err.message.includes('ECONNRESET') || err.message.includes('ECONNREFUSED')) {
        console.log('Error: connection to server broken...')
    }
    else {
        console.error(err);
        process.exit(1);
    }
});

startProxyServer(args);
