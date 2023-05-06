## Steps to start server
1. run `ipconfig getifaddr en0` to get your local IP
2. add a record to point `projectivancheung.online` to your local IP
3. run `yarn` to install dependencies
4. update <b>`host`</b> variable in the index.ts to be your local IP e.g. 192.168.1.167
5. run `yarn ts-node index.ts` to start server
6. access `projectivancheung.online`
