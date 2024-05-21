"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const websocket_1 = __importDefault(require("./components/websocket"));
const koa_1 = __importDefault(require("koa"));
const app = new koa_1.default();
var PORT = 8000;
const server = app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
new websocket_1.default(server);
