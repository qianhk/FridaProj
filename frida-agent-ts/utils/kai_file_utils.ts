import {fileURLToPath} from "url"
import path from "path"
import fs from "fs"
// import moment from "moment"
import {createRequire} from "module";

function scriptRootDir(): string {
    const __filename = fileURLToPath(import.meta.url)
    return path.dirname(path.dirname(__filename))
}

export const script_root_dir = scriptRootDir()
// console.log(`script_root_dir=${script_root_dir}`);

const merge_dir = (parent: string | null, subpath: string | null): string => {
    if (subpath == null || subpath.length === 0) {
        return parent ?? ""
    }
    if (subpath.startsWith("~")) {
        const USER_HOME = process.env.HOME || process.env.USERPROFILE
        // console.log('USER_HOME', USER_HOME)
        return USER_HOME + subpath.substring(1)
    }
    if (subpath.startsWith(".")) {
        return path.resolve(subpath)
    }
    if (parent != null) {
        return path.resolve(parent, subpath)
    } else {
        return subpath
    }
}

const merge_script_dir = (subpath: string | null): string => {
    return merge_dir(script_root_dir, subpath)
}

const writeFileSync = (full_path: string, content_str: string | NodeJS.ArrayBufferView) => {
    let _dirpath = path.dirname(full_path)
    if (!fs.existsSync(_dirpath)) {
        fs.mkdirSync(_dirpath)
    }
    fs.writeFileSync(full_path, content_str)
}

// const getBackupFilePath = (ori_path: string | null, use_time: boolean | null): string => {
//     if (ori_path == null) {
//         return ""
//     }
//     let extname = path.extname(ori_path)
//     if (extname != null && extname.length > 0) {
//         let firstPart = ori_path.substring(0, ori_path.length - extname.length)
//         // console.log('extname', extname, 'firstPart', firstPart)
//         if (use_time == null || !use_time) {
//             return firstPart + '_backup' + extname
//         } else {
//             return firstPart + moment().format("_YYYYMMDDHHmmss") + extname
//         }
//     } else {
//         if (use_time == null || !use_time) {
//             return ori_path + '_backup'
//         } else {
//             return ori_path + moment().format("_YYYYMMDDHHmmss")
//         }
//     }
// }

const requireKaiMinerAddon = () => {
    // KaiLog.log(`process.platform=${process.platform}`)
    let kaiMinerPath = KaiFile.merge_script_dir(`cplusplus/prebuilds/${process.platform}/kaiMiner.node`);
    const require = createRequire(import.meta.url);
    // const kaiMiner = require('bindings')('kaiMiner');
    return require(kaiMinerPath)
}

export const KaiFile = {
    merge_dir,
    merge_script_dir,
    writeFileSync,
    // getBackupFilePath,
    requireKaiMinerAddon,
}
