import { Session, Script } from "frida";
import { MessageType } from "frida/dist/script";
import { readFileSync, existsSync } from "fs";
import path from "path";
import DBManager from "./database";
import WebSocketManager from "./websocket";
import { SessionInfo, App } from "./types";

class REPLManager {
	activeSession: SessionInfo | null;
	session: Session | null;
	app: App | null;
	ws: WebSocketManager;
	dbManager: DBManager;

	constructor(activeSession: SessionInfo, ws: WebSocketManager, dbManager: DBManager) {
		this.activeSession = activeSession;
		this.session = activeSession.session;
		this.app = activeSession.app;
		this.ws = ws;
		this.dbManager = dbManager;
		console.log("REPL Constructor called!");
	}

	async detect_platform(): Promise<void> {
		console.log("Got request for checking device platform");
		const parentDir = path.join(__dirname, "..");
		const filePath = parentDir + "/agents/platform_detector.js";
		
		if (!existsSync(filePath)) {
			this.sendScriptError(`Platform detector script not found at ${filePath}`);
			return;
		}
		
		const fileContent = readFileSync(filePath, "utf8");
		
		try {
			const script = await this.session!.createScript(fileContent);
			
			script.message.connect((message, data) => {
				console.log("Script Message: " + message.type);
				if (message.type === MessageType.Error) {
					const { columnNumber, description, fileName, lineNumber, stack } = message;
					console.log(columnNumber, description, fileName, lineNumber, stack);
					this.sendScriptError({
						description,
						fileName,
						stack,
						line: lineNumber,
						column: columnNumber,
					});
				} else {
					const { payload } = message;
					this.ws.broadcastData(
						JSON.stringify({ action: "detectPlatform", message: payload })
					);
				}
				console.log(data);
			});
			
			script.destroyed.connect(() => {
				console.log("Script destroyed");
			});
			
			await script.load();
		} catch (error) {
			console.error("Error in detect_platform:", error);
			this.sendScriptError(`Failed to load platform detector script: ${error instanceof Error ? error.message : String(error)}`);
		}
	}

	async detect_libraries(): Promise<void> {
		console.log("Got request for detecting libraries");
		const parentDir = path.join(__dirname, "..");
		const filePath = parentDir + "/agents/library_detector.js";
		
		if (!existsSync(filePath)) {
			this.sendScriptError(`Library detector script not found at ${filePath}`);
			return;
		}
		
		const fileContent = readFileSync(filePath, "utf8");
		
		try {
			const script = await this.session!.createScript(fileContent);
			
			script.message.connect((message, data) => {
				console.log("Script Message: " + message.type);
				if (message.type === MessageType.Error) {
					const { columnNumber, description, fileName, lineNumber, stack } = message;
					console.log(columnNumber, description, fileName, lineNumber, stack);
					this.sendScriptError({
						description,
						fileName,
						stack,
						line: lineNumber,
						column: columnNumber,
					});
				} else {
					const { payload } = message;
					try {
						const tmpJson = JSON.parse(payload);
						console.log("[REPL] (detect_libraries) Script message payload:", tmpJson);
						if ("error" in tmpJson) {
							this.sendScriptError({ description: tmpJson.error });
						} else {
							this.ws.broadcastData(
								JSON.stringify({ action: "script.output", message: tmpJson })
							);
						}
					} catch (error) {
						this.sendScriptError(`Error parsing script output: ${error instanceof Error ? error.message : String(error)}`);
					}
				}
				console.log(data);
			});
			
			script.destroyed.connect(() => {
				console.log("Script destroyed");
			});
			
			await script.load();
		} catch (error) {
			console.error("Error in detect_libraries:", error);
			this.sendScriptError(`Failed to load library detector script: ${error instanceof Error ? error.message : String(error)}`);
		}
	}

	async attach_script(code: string, payload: any, manager: any): Promise<void> {
		const parentDir = path.join(__dirname, "..");
		const filePath = parentDir + "/agents/" + code;
		console.log("Attach script payload:", payload);
		const ID = payload.id;
		
		if (!existsSync(filePath)) {
			setTimeout(() => {
				console.log("File doesn't exists");
				this.sendScriptError({ description: `${code} library not found!` });
			}, 2000);
			return;
		}
		
		const fileContent = readFileSync(filePath, "utf8");
		
		try {
			const script = await this.session!.createScript(fileContent);
			
			script.message.connect((message, data) => {
				console.log("Script Message: " + message.type);
				if (message.type === MessageType.Error) {
					const { columnNumber, description, fileName, lineNumber, stack } = message;
					console.log(columnNumber, description, fileName, lineNumber, stack);
					this.sendScriptError({
						description,
						fileName,
						stack,
						line: lineNumber,
						column: columnNumber,
					});
				} else {
					const { payload: messagePayload } = message;
					try {
						const tmpJson = JSON.parse(messagePayload);
						tmpJson.id = ID;
						console.log("[REPL] (attach_script) Script message payload:", tmpJson);
						
						this.ws.broadcastData(
							JSON.stringify({
								action: "repeater.replay.ack",
								replay: JSON.stringify(tmpJson),
							})
						);
						
						this.dbManager.updateReplayedRepeater(tmpJson, (updated: any) => {
							console.log("updated replayed request");
						});
					} catch (error) {
						console.error("Error processing script message:", error);
						this.sendScriptError(`Error processing script response: ${error instanceof Error ? error.message : String(error)}`);
					}
				}
			});
			
			script.destroyed.connect(() => {
				console.log("Script destroyed");
			});
			
			await script.load();
			
			if (payload) {
				script.post({
					type: "data",
					payload: payload,
				});
			}
			
			// this.ws.broadcastData(
			// 	JSON.stringify({
			// 		action: "general.ack",
			// 		message: `${code} library attached!`,
			// 	})
			// );
		} catch (error) {
			console.error("Error attaching script:", error);
			this.sendScriptError(`Failed to attach script ${code}: ${error instanceof Error ? error.message : String(error)}`);
		}
	}

	async run_script(code: string): Promise<void> {
		console.log("Got request for executing code");
		const parentDir = path.join(__dirname, "..");
		const filePath = parentDir + "/libraries/" + code;
		
		if (!existsSync(filePath)) {
			setTimeout(() => {
				console.log("File doesn't exists");
				this.sendScriptError({ description: `${code} library not found!` });
			}, 2000);
			return;
		}
		
		const fileContent = readFileSync(filePath, "utf8");
		
		try {
			const script = await this.session!.createScript(fileContent);
			
			script.message.connect((message, data) => {
				console.log("Script Message: " + message.type);
				if (message.type === MessageType.Error) {
					const { columnNumber, description, fileName, lineNumber, stack } = message;
					console.log(columnNumber, description, fileName, lineNumber, stack);
					this.sendScriptError({
						description,
						fileName,
						stack,
						line: lineNumber,
						column: columnNumber,
					});
				} else {
					const { payload: messagePayload } = message;
					try {
						const tmpJson = JSON.parse(messagePayload);
						console.log("[REPL] (run_script) Response from script:", tmpJson);
						if ("error" in tmpJson) {
							this.sendScriptError({ description: tmpJson.error });
						} else {
							// Save traffic data using the callback-based API
							this.dbManager.writeToTable(tmpJson, (lastId) => {
								if (lastId !== -1) {
									this.dbManager.getRowFromDatabase(lastId, (row) => {
										this.ws.broadcastData(
											JSON.stringify({
												action: "traffic.update.ack",
												message: JSON.parse(row),
											})
										);
									});
								}
							});
						}
					} catch (error) {
						console.error("Error processing script message:", error);
						this.sendScriptError(`Error processing script response: ${error instanceof Error ? error.message : String(error)}`);
					}
				}
				console.log(data);
			});
			
			script.destroyed.connect(() => {
				console.log("Script destroyed");
			});
			
			await script.load();
			
			this.ws.broadcastData(
				JSON.stringify({
					action: "general.ack",
					message: `${code} library attached!`,
				})
			);
			this.ws.broadcastData(
				JSON.stringify({
					action: "library.change.ack",
					library: code,
					message: `${code} library attached!`,
				})
			);
		} catch (error) {
			console.error("Error running script:", error);
			this.sendScriptError(`Failed to run script ${code}: ${error instanceof Error ? error.message : String(error)}`);
		}
	}
	
	// Helper methods to standardize message sending
	private sendScriptError(errorDetails: any): void {
		this.ws.broadcastData(
			JSON.stringify({
				action: "scriptError",
				message: errorDetails,
			})
		);
	}
}

export default REPLManager;
