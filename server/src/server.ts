import WebSocketManager from './components/websocket';
import express, {Router} from 'express';
import unzipper from 'unzipper';
import multer from 'multer';
import { copyFileSync, readdirSync } from 'fs';
import { execSync } from 'child_process';
import DBManager from './components/database';
import { createServer } from 'http';

const app = express();
const router = Router();
const dbManager = new DBManager("./data.db");

const upload = multer({
    dest: 'uploads/'
});

async function checkZipEntries(zipFilePath: string) {
    try {

        const zip = await unzipper.Open.file(zipFilePath);

        const entriesWithDepthOne = [];

        for await (const entry of zip.files) {
            var tmpFilePath = entry.path;
            if(tmpFilePath[tmpFilePath.length - 1] == "/") {
                tmpFilePath = tmpFilePath.slice(0, tmpFilePath.length - 1)
            }
            const pathSegments = tmpFilePath.split('/');
            if (pathSegments.length === 1) {
                entriesWithDepthOne.push(tmpFilePath);
            }
        }

        return entriesWithDepthOne;
    } catch (error) {
        console.error('Error checking zip entries:', error);
        throw error;
    }
}

async function compileFridaAgent(folderPath: string) {
    const tmpResult = execSync('npm install', {cwd: folderPath, encoding: 'utf8'})
    return tmpResult;
}


router.post("/api/intruder_test", async (req: any, res: any) => {   
    
    return res.status(200).json({"status": true, "message": "testing"})
});

router.post("/api/upload", upload.any(), async (req: any, res: any) => {   
    if (!req.files.length) {
        return res.status(200).json({"status": false, "message": 'No file uploaded'});
    }
    
    const file = req.files[0];
    // const unzipPath = "/tmp/agents/"
    // const filePath = "uploads/" + file.filename;
    // await unzipper.Open.file(filePath).then(d => d.extract({path: unzipPath}))
    return res.status(200).json({"status": true, "message": "'"+file.originalname+"' file uploaded successfully!", "filename": file.filename})
});


router.post("/api/setup_library", upload.none(), async (req: any, res: any) => {   
    if (!req.body.filename) {
        return res.status(200).json({"status": false, "message": 'Filename is missing'});
    }
    if(!req.body.platform) {
        return res.status(200).json({"status": false, "message": 'Platform is missing'});
    }
    if(!req.body.library) {
        return res.status(200).json({"status": false, "message": 'Library is missing'});
    }
    const fileName = req.body.filename;
    const unzipPath = "/tmp/agents/"
    const filePath = "uploads/" + fileName;

    var tmpJSONResponse = {}
    const entries = await checkZipEntries(filePath)
    if(entries.length > 1) {
        tmpJSONResponse = {'status': false, 'message': "Invalid ZIP format! ZIP file should have a single folder inside which all the agent files are present including package.json"}
        return res.status(200).json(tmpJSONResponse)
    } else {
        await unzipper.Open.file(filePath).then(d => d.extract({path: unzipPath}))
        var tmpAgentFiles:any = [];
        readdirSync(unzipPath + entries[0]).forEach(file => {
            tmpAgentFiles.push(file);
        });
        if(tmpAgentFiles.indexOf("package.json") > -1) {
            const tmpAgentResult = await compileFridaAgent(unzipPath + entries[0])
            copyFileSync(unzipPath + entries[0] + "/_agent.js", "libraries/" + entries[0] + ".js")
        }
        tmpJSONResponse = {'status': true, 'message': "Library added successfully! Location: 'libraries/" + entries[0] + ".js'"}
        dbManager.createNewLibrary(JSON.stringify({'name': req.body.library, 'file': entries[0] + ".js", 'platform': req.body.platform}), (lastId) => {
            console.log(lastId);
            
        })
        return res.status(200).json(tmpJSONResponse)
    }
});

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
function handleUnknownEndpoint(req: any, res: any) {
// Your specific function to handle unknown endpoints
res.status(404).send('404 - Not Found');
}

var PORT = 8000;
const server = createServer(app);
server.listen(PORT, '0.0.0.0', ()=> {
    console.log(`Server listening on port ${PORT}`);
})
new WebSocketManager(server);

