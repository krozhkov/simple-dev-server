import { valueAt } from './utils';

export interface CommandLineArguments {
    config?: string;
    user?: string;
    password?: string;
}

export function readCommandLine(args: string[]): CommandLineArguments {
    if (args.length === 0) {
        showHelp();
        return process.exit(1);
    }

    const result: CommandLineArguments = {};

    for (let i = 0; i < args.length; i++) {
        const arg = valueAt(args, i);
        switch (arg) {
            case '-config':
                i++;
                result.config = valueAt(args, i);
                break;
            case '-user':
                i++;
                result.user = valueAt(args, i);
                break;
            case '-password':
                i++;
                result.password = valueAt(args, i);
                break;
            default:
                console.error('Unexpected argument \'' + arg + '\'.');
                showHelp();
                return process.exit(1);
        }
    }

    return result;
}

function showHelp(): void {
    console.log(`Usage: run -config [path_to_config_file] -user [user_name] -password [password]`);
}
