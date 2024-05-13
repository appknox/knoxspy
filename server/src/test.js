var frida = require("frida")

const mgr = frida.getDeviceManager()

async function test() {
    const devices = await mgr.enumerateDevices()
    console.log(devices)
}

test()