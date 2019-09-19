@echo off
call node --max_old_space_size=2048 ./node_modules/typescript/bin/tsc --project ./tsconfig.json
IF %ERRORLEVEL% NEQ 0 (
   echo "Unable to build the code."
   exit /b 1
)
call node ./built/run.js %*