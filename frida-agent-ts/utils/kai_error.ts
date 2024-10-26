import {KaiStr} from "./kai_string_utils.js"

const simpleErrorMsg = (e: any): string => {
    if (e == null) {
        return "null"
    } else if (typeof e === "string") {
        return e;
    } else {
        let message = e.shortMessage
        if (message == null) {
            message = e.message
        }
        if (message == null) {
            message = "未知Error类型：" + e.toString()
        }
        if (e.info != null && e.info.error != null) {
            let _msg = e.info.error.message
            if (KaiStr.isNotEmptyString(_msg)) {
                message = _msg
            }
        }
        let prefix = e.code
        if (prefix == null) {
            prefix = e.name
        }
        if (e.cause != null && e.cause.message != null) {
            return `${prefix}::${message}, cause: ${e.cause.message}`
        } else if (e.response != null && e.response.data != null && e.response.data.length > 0) {
            return `${prefix}::${message}, response.data: ${e.response.data}`
        } else {
            return `${prefix}::${message}`
        }
    }
}

const isInsufficientFundsError = (e: any): boolean => {
    if (e == null) {
        return false
    }

    const noFundsList = [
        'does not exist on chain', // inj? cosmos?
        'insufficient funds',
        'account balance too low', // dot
        'Attempt to debit an account but found no record of a prior credit', // sol
    ]
    const eStr = e.toString()
    for (let noFundsStr of noFundsList) {
        if (eStr.indexOf(noFundsStr) >= 0) {
            return true
        }
    }

    return false;
}

const isNetworkError = (e: any): boolean => {
    if (e == null) {
        return false
    }

    const networkErrorList = [
        'TypeError: fetch failed',
    ]
    const eStr = e.toString()
    for (let networkErrorStr of networkErrorList) {
        if (eStr.indexOf(networkErrorStr) >= 0) {
            return true
        }
    }

    return false;
}

const isProcessInstructionError = (e: any): boolean => {
    if (e == null) {
        return false
    }

    const instructionList = [
        'Error processing Instruction',
    ]
    const eStr = e.toString()
    for (let instructionStr of instructionList) {
        if (eStr.indexOf(instructionStr) >= 0) {
            return true
        }
    }

    return false;
}

export const KaiError = {
    simpleErrorMsg,
    isInsufficientFundsError,
    isNetworkError,
    isProcessInstructionError,
}
