import {KaiLog} from "../utils/kai_log.js";
import path from "path";
import {KaiUtils} from "../utils/kai_utils.js";
import {
    lookOcClassMethod,
    lookOcModuleBaseAddress,
    objcApiResolverTest,
    ocInvokeFunction,
    ocTestClass,
    ocTestEntry,
    ocTestInstance,
    ocTestZaVcMethodInstance, ocTestZaVcMethodInstance2
} from "./oc_test.js";

console.log('\n\n\n');
KaiLog.log('Kai Script loaded successfully.');
KaiLog.log(`Process.arch=${Process.arch}`); // arm x64

// Hook 大法，拦截器的使用 (iOS) https://bbs.kanxue.com/thread-259424.htm
// Frida学习笔记（iOS为主） https://blog.csdn.net/Morphy_Amo/article/details/121758208
// frida-all-in-one https://github.com/hookmaster/frida-all-in-one
// Frida Android hook https://eternalsakura13.com/2020/07/04/frida/

const header = Memory.alloc(16);
header
    .writeU32(0xdeadbeef).add(4)
    .writeU32(0xd00ff00d).add(4)
    .writeU64(uint64("0x1122334455667788"));
console.log(hexdump(header.readByteArray(16) as ArrayBuffer, {ansi: true}));

Process.getModuleByName("libSystem.B.dylib")
    .enumerateExports()
    .slice(0, 16)
    .forEach((exp, index) => {
        KaiLog.log(`export ${index}: ${exp.name}`);
    });

Interceptor.attach(Module.getExportByName(null, "open"), {
    onEnter(args) {
        const path = args[0].readUtf8String() ?? "";
        if (path.indexOf('Kai') >= 0) {
            KaiLog.log(`open() path="${path}"`);
        }
    }
});

KaiLog.log(`ObjC.available=${ObjC.available}`)

let macOsProgram = false;
if (macOsProgram) {
    const moduleName = "KaiCDemo";
    let baseAddress = Module.findBaseAddress(moduleName);
    KaiLog.log("\n" + "base : " + baseAddress);
    if (baseAddress != null) {
        console.log(hexdump(baseAddress), {
            length: 16,
            header: true,
            ansi: true,
        })
        let fun_addr = baseAddress.add(0x1190);
        KaiLog.log(`fun_addr : ${fun_addr}`);
        console.log(hexdump(fun_addr), {
            length: 16,
            header: true,
            ansi: true,
        })
    }
} else {
    ocTestEntry();
    lookOcModuleBaseAddress();
    objcApiResolverTest();
    // ocTestClass();
    ocTestInstance();
    ocInvokeFunction();
    lookOcClassMethod('KaiStudent')
    ocTestZaVcMethodInstance();
    ocTestZaVcMethodInstance2();
}

let testFunPointer = Module.findExportByName(null, "testFun");
KaiLog.log(`testFunPointer=${testFunPointer}`);
if (testFunPointer != null) {
    // Interceptor.attach(ptr("0x10c965190"), {
    Interceptor.attach(testFunPointer, {
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

            let backtraceList = Thread.backtrace(this.context, Backtracer.ACCURATE);
            let newBacktraceList = backtraceList.map(DebugSymbol.fromAddress);
            let tmpStr = newBacktraceList.join("\n\t");
            KaiLog.log(`called from:\n${tmpStr}`);
        },
        onLeave(returnValue) {
            KaiLog.log(`onLeave f func returnValue=${returnValue.toInt32()}`);
            this.keepStrPointer = null;
            returnValue.replace(ptr(KaiUtils.getRandomNum(1000, 9999)));
        }
    });

    let testFunFunction = new NativeFunction(testFunPointer, 'int', ['int', 'pointer'])
    Interceptor.replace(testFunFunction, new NativeCallback((param1, param2) => {
        KaiLog.log(`replace param1=${param1} param2=${param2.readUtf8String()}`)
        if (param1 == 0) {
            return testFunFunction(param1, param2);
        } else {
            return param1 + 1000;
        }
    }, 'int', ['int', 'pointer']));
}

/*
if (Process.arch == 'arm')
      return func_addr.add(1);  //如果是32位地址+1
   else
      return func_addr;

hopper里：
 _testFun:
0000000100001190         push       rbp

testFun() address is at 0x10e182190
[19:47:35.567] base : 0x10e181000
            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
10e181000  cf fa ed fe 07 00 00 01 03 00 00 00 02 00 00 00  基址内存中的数据是 cf fa ed fe，说明是 Mach-O 头部，确实是可执行文件
[19:47:35.568] fun_addr : 0x10e182190
            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
10e182190  55 48 89 e5 48 83 ec 10 89 7d fc 48 89 75 f0 8b  UH..H....}.H.u..
[19:47:35.569] testFunPointer=0x10e182190
 */