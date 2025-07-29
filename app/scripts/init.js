const cp = require("child_process");

const tasks = {
  client: {
    cmd: "vite",
    args: ["--host"],
    cwd: "../gui",
  },
  server: {
    cmd: "npx",
    args: ["nodemon", "server.ts"],
    cwd: "../server",
  },
};

function run() {
  for (var task in tasks) {
    const { cmd, args, cwd } = tasks[task];
    cp.spawn(cmd, args, { cwd });
    console.log("Spawned", task);
  }
}

run();
