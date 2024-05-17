import WebSocketManager from './components/websocket';
import { readFileSync } from 'fs';
import {createServer} from 'http';
import { WebSocket, Server } from 'ws';
import Koa from 'koa';

const app = new Koa();



var PORT = 8000;

const server = app.listen(PORT, ()=> {
    console.log(`Server listening on port ${PORT}`);
})
new WebSocketManager(server);
