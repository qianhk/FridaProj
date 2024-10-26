import {KaiLog} from "../utils/kai_log.js";
import path from "path";
import {KaiUtils} from "../utils/kai_utils.js";

KaiLog.log('Kai Script loaded successfully.');

const header = Memory.alloc(16);
header
    .writeU32(0xdeadbeef).add(4)
    .writeU32(0xd00ff00d).add(4)
    .writeU64(uint64("0x1122334455667788"));
console.log(hexdump(header.readByteArray(16) as ArrayBuffer, { ansi: true }));

Process.getModuleByName("libSystem.B.dylib")
    .enumerateExports()
    .slice(0, 16)
    .forEach((exp, index) => {
        KaiLog.log(`export ${index}: ${exp.name}`);
    });

Interceptor.attach(Module.getExportByName(null, "open"), {
    onEnter(args) {
        const path = args[0].readUtf8String();
        KaiLog.log(`open() path="${path}"`);
    }
});

Interceptor.attach(ptr("0x10c965190"), {
    onEnter(args) {
        let arg0 = args[0].toInt32();
        let arg1 = args[1].readCString();
        // args[0].writeInt(123) // Error: access violation accessing xxx
        // args[1] = ptr("haha modify str") // expected a pointer
        let newStrPointer = Memory.allocUtf8String("abc_xyz");
        args[1] = newStrPointer;
        this.keepStrPointer = Memory.allocUtf8String("abc_xyz2");
        args[1] = this.keepStrPointer;
        KaiLog.log(`onEnter f func arg0=${arg0} arg1=${arg1} arg1_new=${this.keepStrPointer.readCString()}`);
    },
    onLeave(returnValue) {
        KaiLog.log(`onLeave f func returnValue=${returnValue.toInt32()}`);
        this.keepStrPointer = null;
        returnValue.replace(ptr(KaiUtils.getRandomNum(1000, 9999)));
    }
});
