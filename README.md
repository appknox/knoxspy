# MDM Dashboard

<img width="1439" alt="image" src="https://github.com/ajay-appknox/mdm_dashboard/assets/98275091/a6c05942-be1c-4b3b-bb68-373a9a6faf57">


## Installation
```bash
git clone https://github.com/ajay-appknox/mdm_dashboard.git
```

### Setting Up Client
Create .env file with VITE_SERVER_IP. The client will be using this environment variable to connect to server.\
> Note: This file needs to be created under client folder.
```bash
echo 'VITE_SERVER_IP=<SERVER_IP>' > .env
```

### Client
```bash
cd client;
npm install;
vite --host;
```

### Server
```bash
cd server;
npm install;
npm install --save-dev nodemon ts-node;
cd src;
npx nodemon server.ts;
```
