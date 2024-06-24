"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __asyncValues = (this && this.__asyncValues) || function (o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const websocket_1 = __importDefault(require("./components/websocket"));
const express_1 = __importStar(require("express"));
const unzipper_1 = __importDefault(require("unzipper"));
const multer_1 = __importDefault(require("multer"));
const fs_1 = require("fs");
const child_process_1 = require("child_process");
const database_1 = __importDefault(require("./components/database"));
const http_1 = require("http");
const app = (0, express_1.default)();
const router = (0, express_1.Router)();
const dbManager = new database_1.default("./data.db");
const cors = require('cors');
const upload = (0, multer_1.default)({
    dest: 'uploads/'
});
// const corsOptions = {
//     origin: '*', // Specify the allowed origin
//     methods: 'GET,HEAD,PUT,PATCH,POST,DELETE', // Specify allowed methods
//     optionsSuccessStatus: 204 // Some legacy browsers choke on 204
//   };
app.use(cors());
function checkZipEntries(zipFilePath) {
    return __awaiter(this, void 0, void 0, function* () {
        var _a, e_1, _b, _c;
        try {
            const zip = yield unzipper_1.default.Open.file(zipFilePath);
            const entriesWithDepthOne = [];
            try {
                for (var _d = true, _e = __asyncValues(zip.files), _f; _f = yield _e.next(), _a = _f.done, !_a; _d = true) {
                    _c = _f.value;
                    _d = false;
                    const entry = _c;
                    var tmpFilePath = entry.path;
                    if (tmpFilePath[tmpFilePath.length - 1] == "/") {
                        tmpFilePath = tmpFilePath.slice(0, tmpFilePath.length - 1);
                    }
                    const pathSegments = tmpFilePath.split('/');
                    if (pathSegments.length === 1) {
                        entriesWithDepthOne.push(tmpFilePath);
                    }
                }
            }
            catch (e_1_1) { e_1 = { error: e_1_1 }; }
            finally {
                try {
                    if (!_d && !_a && (_b = _e.return)) yield _b.call(_e);
                }
                finally { if (e_1) throw e_1.error; }
            }
            return entriesWithDepthOne;
        }
        catch (error) {
            console.error('Error checking zip entries:', error);
            throw error;
        }
    });
}
function compileFridaAgent(folderPath) {
    return __awaiter(this, void 0, void 0, function* () {
        const tmpResult = (0, child_process_1.execSync)('npm install', { cwd: folderPath, encoding: 'utf8' });
        return tmpResult;
    });
}
router.post("/api/intruder_test", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    return res.status(200).json({ "status": true, "message": "testing" });
}));
router.post("/api/upload", upload.any(), (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    if (!req.files.length) {
        return res.status(200).json({ "status": false, "message": 'No file uploaded' });
    }
    const file = req.files[0];
    // const unzipPath = "/tmp/agents/"
    // const filePath = "uploads/" + file.filename;
    // await unzipper.Open.file(filePath).then(d => d.extract({path: unzipPath}))
    return res.status(200).json({ "status": true, "message": "'" + file.originalname + "' file uploaded successfully!", "filename": file.filename });
}));
router.post("/api/setup_library", upload.none(), (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    if (!req.body.filename) {
        return res.status(200).json({ "status": false, "message": 'Filename is missing' });
    }
    if (!req.body.platform) {
        return res.status(200).json({ "status": false, "message": 'Platform is missing' });
    }
    if (!req.body.library) {
        return res.status(200).json({ "status": false, "message": 'Library is missing' });
    }
    const fileName = req.body.filename;
    const unzipPath = "/tmp/agents/";
    const filePath = "uploads/" + fileName;
    var tmpJSONResponse = {};
    const entries = yield checkZipEntries(filePath);
    if (entries.length > 1) {
        tmpJSONResponse = { 'status': false, 'message': "Invalid ZIP format! ZIP file should have a single folder inside which all the agent files are present including package.json" };
        return res.status(200).json(tmpJSONResponse);
    }
    else {
        yield unzipper_1.default.Open.file(filePath).then(d => d.extract({ path: unzipPath }));
        var tmpAgentFiles = [];
        (0, fs_1.readdirSync)(unzipPath + entries[0]).forEach(file => {
            tmpAgentFiles.push(file);
        });
        if (tmpAgentFiles.indexOf("package.json") > -1) {
            const tmpAgentResult = yield compileFridaAgent(unzipPath + entries[0]);
            (0, fs_1.readdirSync)(".").forEach(file => {
                console.log(file);
            });
            (0, fs_1.copyFileSync)(unzipPath + entries[0] + "/_agent.js", "libraries/" + entries[0] + ".js");
        }
        tmpJSONResponse = { 'status': true, 'message': "Library added successfully! Location: 'libraries/" + entries[0] + ".js'" };
        dbManager.createNewLibrary(JSON.stringify({ 'name': req.body.library, 'file': entries[0] + ".js", 'platform': req.body.platform }), (lastId) => {
            console.log(lastId);
        });
        return res.status(200).json(tmpJSONResponse);
    }
}));
app.use((req, res, next) => {
    const method = req.method;
    const endpoint = req.originalUrl;
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${method} request to ${endpoint}`);
    next();
});
app.use(router);
app.use((req, res) => {
    console.log('Unknown endpoint requested:', req.originalUrl);
    handleUnknownEndpoint(req, res);
});
// Function to handle unknown endpoints
function handleUnknownEndpoint(req, res) {
    // Your specific function to handle unknown endpoints
    res.status(404).send('404 - Not Found');
}
var PORT = 8000;
const server = (0, http_1.createServer)(app);
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server listening on port ${PORT}`);
});
new websocket_1.default(server);
