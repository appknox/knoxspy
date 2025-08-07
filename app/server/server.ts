import WebSocketManager from "./src/websocket";
import express, { Router, Request, Response, NextFunction } from "express";
import unzipper from "unzipper";
import multer from "multer";
import { copyFileSync, readdirSync, mkdirSync, existsSync } from "fs";
import path from "path";
import { execSync } from "child_process";
import DBManager from "./src/database";
import { createServer } from "http";
import { LibraryData } from "./src/types";
import cors from "cors";

// Initialize Express and middlewares
const app = express();
const router = Router();
const dbManager = new DBManager("./data.db");

// Configure multer for file uploads
const upload = multer({
	dest: "uploads/",
	limits: {
		fileSize: 50 * 1024 * 1024, // 50MB limit
	},
});

// Configure CORS
app.use(cors());
app.use(express.json());

// Ensure required directories exist
const requiredDirs = ["uploads", "libraries"];
for (const dir of requiredDirs) {
	if (!existsSync(dir)) {
		mkdirSync(dir, { recursive: true });
	}
}

/**
 * Checks entries in a zip file and returns top-level entries
 * @param zipFilePath Path to the zip file
 * @returns List of entries at depth one
 */
async function checkZipEntries(zipFilePath: string): Promise<string[]> {
	try {
		const zip = await unzipper.Open.file(zipFilePath);
		const entriesWithDepthOne: string[] = [];

		for await (const entry of zip.files) {
			let tmpFilePath = entry.path;
			if (tmpFilePath.endsWith("/")) {
				tmpFilePath = tmpFilePath.slice(0, -1);
			}
			const pathSegments = tmpFilePath.split("/");
			if (pathSegments.length === 1) {
				entriesWithDepthOne.push(tmpFilePath);
			}
		}

		return entriesWithDepthOne;
	} catch (error) {
		console.error("Error checking zip entries:", error);
		throw error;
	}
}

/**
 * Compiles a Frida agent from source files
 * @param folderPath Path to the folder containing agent source
 */
async function compileFridaAgent(folderPath: string): Promise<void> {
	try {
		const result = execSync(
			`cd ${folderPath} && frida-compile -o ${path.join(folderPath, "_library.js")} agent/index.ts`,
			{ timeout: 30000 }
		);
		console.log(result.toString());
	} catch (error) {
		console.error("Error compiling Frida agent:", error);
		throw error;
	}
}

// API Routes
router.get("/connected", async (req: Request, res: Response) => {
	console.log("Checking active session");
	const activeSession = wsManager.getActiveSession();
	return res.status(200).json(activeSession);
});

router.post("/sync/selection", async (req: Request, res: Response) => {
	const selectionData = req.body;
	if (!selectionData) {
		return res.status(400).json({ status: false, message: "No selection data provided" });
	}
	wsManager.setSelection(selectionData);
	
	return res.status(200).json({
		status: true,
		message: "Selection data synced successfully"
	});
});

router.get("/sync/selection", async (req: Request, res: Response) => {
	const activeSession = wsManager.getSelection();
	if (!activeSession) {
		return res.status(404).json({ status: false, message: "No active session or selection data found" });
	}
	return res.status(200).json({
		status: true,
		selection: activeSession || {},
		message: "Selection data retrieved successfully"
	});
});

router.post("/upload", upload.single("file"), async (req: Request, res: Response) => {
	if (!req.file) {
		return res.status(400).json({ status: false, message: "No file uploaded" });
	}

	return res.status(200).json({
		status: true,
		message: `'${req.file.originalname}' file uploaded successfully!`,
		filename: req.file.filename,
	});
});

router.post(
	"/setup_library",
	upload.none(),
	async (req: Request, res: Response) => {
		const { filename, platform, library } = req.body;

		// Validate required fields
		if (!filename) {
			return res
				.status(400)
				.json({ status: false, message: "Filename is missing" });
		}
		if (!platform) {
			return res
				.status(400)
				.json({ status: false, message: "Platform is missing" });
		}
		if (!library) {
			return res
				.status(400)
				.json({ status: false, message: "Library is missing" });
		}

		const filePath = path.join("uploads", filename);
		const unzipPath = path.join("/tmp", "agents");

		// Ensure unzip directory exists
		if (!existsSync(unzipPath)) {
			mkdirSync(unzipPath, { recursive: true });
		}

		try {
			// Check if the file exists
			if (!existsSync(filePath)) {
				return res
					.status(404)
					.json({ status: false, message: "Uploaded file not found" });
			}

			// Check ZIP file structure
			const entries = await checkZipEntries(filePath);
			if (entries.length !== 1) {
				return res.status(400).json({
					status: false,
					message:
						"Invalid ZIP format! ZIP file should have a single folder inside which all the agent files are present including package.json",
				});
			}

			// Extract the ZIP
			await unzipper.Open.file(filePath).then((d) =>
				d.extract({ path: unzipPath })
			);

			const extractedDir = path.join(unzipPath, entries[0]);

			// Check files in the extracted directory
			const tmpAgentFiles = readdirSync(extractedDir);

			// Compile and copy agent if package.json exists
			if (tmpAgentFiles.includes("package.json")) {
				await compileFridaAgent(extractedDir);

				const outputFile = path.join("libraries", `${entries[0]}.js`);
				const compiledFile = path.join(extractedDir, "_library.js");

				if (!existsSync(compiledFile)) {
					return res.status(500).json({
						status: false,
						message: "Failed to compile the agent",
					});
				}

				copyFileSync(compiledFile, outputFile);
			} else {
				return res.status(400).json({
					status: false,
					message: "package.json not found in the agent directory",
				});
			}

			// Add library to database
			const libraryData: Partial<LibraryData> = {
				name: library,
				file: `${entries[0]}.js`,
				platform,
			};

			await dbManager.createNewLibrary(libraryData);

			return res.status(200).json({
				status: true,
				message: `Library added successfully! Location: 'libraries/${entries[0]}.js'`,
			});
		} catch (error) {
			console.error("Error setting up library:", error);
			return res.status(500).json({
				status: false,
				message: `Error setting up library: ${
					error instanceof Error ? error.message : String(error)
				}`,
			});
		}
	}
);

app.use("/api", router);

// Create HTTP server and WebSocket manager
const server = createServer(app);
const wsManager = new WebSocketManager(server, dbManager);

// Start the server
const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});

// Handle graceful shutdown
process.on("SIGTERM", () => {
	console.log("Received SIGTERM, shutting down gracefully");
	server.close(() => {
		console.log("Server closed");
		process.exit(0);
	});
});
