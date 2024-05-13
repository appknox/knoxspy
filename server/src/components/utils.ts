
import * as child from 'child_process';
import Channels from './channels';
import * as frida from 'frida';
import { Scope } from 'frida/dist/device';

export function bytesToImageURI(byteArray: any) {
    const stringData = String.fromCharCode(...byteArray);
    const base64Data = btoa(stringData);
    const mimeType = 'image/png';
    const dataURI = `data:${mimeType};base64,${base64Data}`;
    return dataURI;
}

export function split_by_length(arr1: string[], arr2: number[], sum: number) {
    var result = Array();
    // console.log(arr2)
    for (let i = 0; i < arr1.length; i++) {
        var string = arr1[i];
        // console.log("Prev: " + " | " + string + " | " + string.length + " | " + sum);
        if (string.length < sum) {
            string += " ".repeat(sum-string.length)
        }
        // console.log("Next: " + " | " + string + " | " + string.length + " | " + sum);
        // console.log(string + "|")
        var acc_str_arr = [];
        var acc_str = string;
        for(const x in arr2) {
            // console.log(arr2[x])
            const tmp_str = acc_str.slice(0, arr2[x])
            // console.log(tmp_str)
            // console.log(tmp_str + " | " + tmp_str.length)
            // console.log(acc_str.slice(arr2[x]))
            acc_str = acc_str.slice(arr2[x])
            acc_str_arr.push(tmp_str.trim())
        }
        acc_str_arr.push(acc_str.trim())
        const acc_str_obj = {"id": acc_str_arr[0], "type": acc_str_arr[1], "name": acc_str_arr[2], "os": acc_str_arr[3]}
        // console.log(acc_str_arr)
        result.push(acc_str_obj);
        // break;
    }
    // console.log(result)
    return result;
}

export function parseDevices(out: string) {
    const s_length: number[] = out.split("\n")[1].split("  ").map((item: string) => item.length);
    var length_arr = [];
    for(var i=0;i<s_length.length;i++) {
        var prev: number = 0;
        if (i) {
            prev = s_length[i-1] + 2;
            length_arr.push(prev);
        }
    }
    var sum: number = 6;
    for (const num of s_length) {
        sum += num;
    }
    
    const arr = out.split("\n");
    arr.shift();
    arr.shift();
    
    // console.log(arr)
    // console.log(sum)
    // console.log(length_arr)
    return split_by_length(arr, length_arr, sum)
}

export async function findDevices() {
    const stdout = await child.execSync('frida-ls-devices');
    const arr = stdout.toString();
    const unique = Array()
    const allowedDeviceTypes = ["local", "remote", "barebone"];
    const devices = parseDevices(arr.trim())
    const filtered = devices.filter(dev => !allowedDeviceTypes.includes(dev.type));
    for(const dev in filtered) {
        const {id, name, type} = filtered[dev];
        const filteredDevice = {id, name, type};
        unique.push(filteredDevice)
    }
    return unique;
}

export async function findApps(deviceId: string) {
    const mgr = frida.getDeviceManager()
    const devices = await mgr.enumerateDevices();
    const filtered = devices.filter(dev => deviceId == dev.id);
    const device = filtered[0];
    const applications = await device.enumerateApplications({ scope: Scope.Full });
    const filteredApplications = [];
    for(const app in applications) {
        const appsDetails = {}
        const appInfo = applications[app];
        const params = applications[app].parameters;
        if (params.icons?.length) {
            if(params.icons[0].format === "png") {
                const appsDetails = {"icon": bytesToImageURI(params.icons[0].image), "identifier": appInfo.identifier, "name": appInfo.name}
                filteredApplications.push(appsDetails);
            }
        }
    }
    return filteredApplications;
}

export async function startApp(deviceId: string, appId: string) {
    const mgr = frida.getDeviceManager()
    const devices = await mgr.enumerateDevices();
    const filtered = devices.filter(dev => deviceId == dev.id);
    const device = filtered[0];
    const pid = await device.spawn(appId)
    device.resume(pid)
    const session = await device.attach(pid)
    return session;
}