import {KaiLog} from "./kai_log.js";
import {KaiError} from "./kai_error.js";

function sleep(time: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, time));
}

// @ts-ignore
BigInt.prototype.toJSON = function () {
    return this.toString();
};

function configAxios() {
    // const httpsAgent = new https.Agent({
    //     rejectUnauthorized: false,
    // });
    // axios.defaults.timeout = 15000 // 15秒延迟, 默认0好像无限等待
    // axios.defaults.headers.common['User-Agent'] = userAgent
    // axios.defaults.httpsAgent = httpsAgent
}

function setProcessExitHandler(handleExit: (code: number, error?: any) => void) {
    // https://juejin.cn/post/7081222436503027742
    // 监听各种退出事件
    // process.on('exit', code => this.handleExit(code)); //似乎多余，调用 process.exit(0) 也会触发，没必要的样子
    // 按照 POSIX 的规范，我们用 128 + 信号编号 得到最终的退出码
    // 信号编号参考下面的图片，大家可以在 linux 系统下执行 kill -l 查看所有的信号编号
    process.on('SIGHUP', () => handleExit(128 + 1)); //直接关闭命令行终端
    process.on('SIGINT', () => {
        // console.log('receive sigint event')
        return handleExit(128 + 2);
    }); //ctrl + c
    process.on('SIGTERM', () => handleExit(128 + 15)); //
    // windows 下按下 ctrl+break 的退出信号
    process.on('SIGBREAK', () => handleExit(128 + 21));
    // 退出码 1 代表未捕获的错误导致进程退出
    process.on('uncaughtException', error => handleExit(1, error));
    process.on('unhandledRejection', error => handleExit(1, error));
}

function arrayGroup<T>(array: T[], subGroupLength: number): T[][] {
    let index = 0;
    let newArray: T[][] = [];

    while (index < array.length) {
        newArray.push(array.slice(index, index += subGroupLength));
    }

    return newArray;
}

async function asyncInsureExecute<T>(fn: () => Promise<T>, delayMsIfFailed?: number | null): Promise<T> {
    while (true) {
        try {
            // KaiLog.log(`in asyncInsureExecute while fn=${fn}`)
            // const result = await fn();
            // KaiLog.log('after invoke fn()')
            // return result;
            return await fn();
        } catch (e) {
            // const isNetworkFailed = KaiError.isNetworkError(e);
            // KaiLog.log(`isNetworkFailed=${isNetworkFailed}`);
            KaiLog.log(`asyncInsureExecute error, delay again, fn=${fn} e=${e}`);
            await KaiUtils.sleep(delayMsIfFailed ?? 2000);
        }
    }
}

const isUint8ArrayEqual = (arr1: Uint8Array, arr2: Uint8Array): boolean => {
    if (arr1.length !== arr2.length) {
        return false
    }

    return arr1.every((value, index) => value === arr2[index])
}

const getRandomNum = (min: number, max: number): number => {
    let range = max - min;
    let rand = Math.random();
    return min + Math.round(rand * range);
}

const stringHasPrefixWithCertList = (str: string, list: string[]): boolean => {
    for (let _p of list) {
        if (str.startsWith(_p)) {
            return true;
        }
    }
    return false;
}


export const KaiUtils = {
    sleep,
    setProcessExitHandler,
    arrayGroup,
    asyncInsureExecute,
    isUint8ArrayEqual,
    getRandomNum,
    stringHasPrefixWithCertList,
}
