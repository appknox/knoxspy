import { spawn } from "child_process";

const tasks = {
  client: {
    cmd: "vite",
    args: ["--host"],
    cwd: "src/gui",
  },
  server: {
    cmd: "npx",
    args: ["nodemon", "server.ts"],
    cwd: "src/server",
  },
};

function run() {
  for (var task in tasks) {
    const { cmd, args, cwd } = tasks[task];
    spawn(cmd, args, { cwd });
    console.log("Spawned", task);
  }
}

run();
