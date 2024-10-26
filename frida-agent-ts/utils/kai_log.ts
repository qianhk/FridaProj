import path from "path"

// @ts-ignore
BigInt.prototype.toJSON = function() {
    return this.toString();
};

const getLogTimeStr = () => {
    const dt = new Date();
    let hour = dt.getHours();
    let minute = dt.getMinutes();
    let second = dt.getSeconds();
    let milliseconds = dt.getMilliseconds();
    return `[${hour.toString().padStart(2, "0")}:${minute.toString().padStart(2, "0")}:${second.toString().padStart(2, "0")}.${milliseconds.toString().padStart(3, "0")}]`;
}

const log = (...logstrs: any[]) => {
    if (logstrs != null && logstrs.length > 0) {
        let firstStr = logstrs[0]
        if (firstStr != null && firstStr.length > 0 && firstStr[0] === '\n') {
            console.log("\n" +getLogTimeStr()
                , firstStr.substring(1), ...logstrs.slice(1))
        } else {
            console.log(getLogTimeStr(), ...logstrs)
        }
    } else {
        console.log(getLogTimeStr(), ...logstrs)
    }
}

export const KaiLog = {
    log
}
