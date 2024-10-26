function isEmptyString(str: any | null): boolean {
    return str == null || typeof (str) !== "string" || str.length === 0
}

const isNotEmptyString = (str: any | null): boolean => {
    return str != null && typeof (str) === "string" && str.length > 0
}

/**
 * 返回的是供人阅读的字符串，保留最大maxDecimals位小数
 */
const removeBalanceRedundantZero = (oriBalance: null | string | number | bigint, maxDecimals?: number): string => {
    if (oriBalance == null) {
        return ""
    }
    let newBalance: string
    if (typeof oriBalance !== "string") {
        newBalance = oriBalance.toString()
    } else {
        newBalance = oriBalance;
    }
    const dotPos = newBalance.indexOf('.')
    if (dotPos >= 0) {
        if (maxDecimals != null && maxDecimals >= 0) {
            newBalance = newBalance.substring(0, dotPos + maxDecimals + 1)
        }
    }
    let zeroCount = 0
    for (let idx = newBalance.length - 1; idx > dotPos; --idx) {
        if (newBalance[idx] === '0') {
            ++zeroCount
        } else {
            break;
        }
    }
    if (zeroCount > 0) {
        newBalance = newBalance.substring(0, newBalance.length - zeroCount)
    }
    if (newBalance.endsWith('.')) {
        newBalance = newBalance.substring(0, newBalance.length - 1)
    }
    return newBalance
}

function isBase64(str: string): boolean {
    if (isEmptyString(str)) {
        return false;
    }
    try {
        return btoa(atob(str)) === str;
    } catch (err) {
        return false;
    }
}

function stringToHex(string: string): string {
    if (isEmptyString(string)) {
        return string;
    }
    if (string.startsWith('0x')) {
        return string
    }
    return '0x' + Buffer.from(string, 'utf8').toString('hex');
}

function stringToBase64(string: string): string {
    if (isEmptyString(string)) {
        return string;
    }
    if (KaiStr.isBase64(string)) {
        return string
    }
    return Buffer.from(string).toString('base64')
}

function decodeBase64(string: string): string {
    if (isEmptyString(string)) {
        return string;
    }
    return Buffer.from(string, 'base64').toString()
}

// uint8 转成 16进制字符，整个字符串不含 0x
// 如 [61, 62, 30, 31, ...] 转成 "ab01" ，不含 前缀0x
// 不支持中文等非普通字母数字的
function uint8ArrayToString(unit8Array: Uint8Array): string {
    let dataString = "";
    for (let i = 0; i < unit8Array.length; ++i) {
        dataString += String.fromCharCode(unit8Array[i]);
    }

    return dataString
}

// bigint => 16进制字符串，含0x前缀
// 长度不足paddingZeroToLen要求时，前面补0，len的长度计算不含0x
function bigintToHexString(bigIntValue: bigint, addZeroToLen: number): string {
    const hexStr = bigIntValue.toString(16);
    const needZeroLen = addZeroToLen - hexStr.length;
    let result = '0x';
    for (let idx = 0; idx < needZeroLen; ++idx) {
        result += '0'
    }
    return result + hexStr;
}

export const KaiStr = {
    isEmptyString,
    isNotEmptyString,
    removeBalanceRedundantZero,
    isBase64,
    stringToHex,
    stringToBase64,
    decodeBase64,
    uint8ArrayToString,
    bigintToHexString,
}

