import WebSocketManager from './components/websocket';
import { readFileSync } from 'fs';
import {createServer} from 'http';
import { WebSocket, Server } from 'ws';
import Koa from 'koa';

const app = new Koa();



var PORT = 8000;

// const cts = {
//     cert: readFileSync("./server-cert.pem"),
//     key: readFileSync("./server-key.pem")
// }
// const server = createServer(cts, (req, res) => {
//     res.writeHead(200);
//     res.end('hello world\n');
// }).listen(PORT)

// const server = createServer(app.callback)

const server = app.listen(PORT, ()=> {
    console.log(`Server listening on port ${PORT}`);
})
const webSocketManager = new WebSocketManager(server);
