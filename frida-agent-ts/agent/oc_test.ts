import {KaiLog} from "../utils/kai_log.js";

// 在iOS上使用Frida
// https://mabin004.github.io/2018/08/24/%E5%9C%A8iOS%E4%B8%8A%E4%BD%BF%E7%94%A8Frida/

/*
NSData转String
var data = new ObjC.Object(args[2]);
Memory.readUtf8String(data.bytes(), data.length());

NSData转二进制数据
var data = new ObjC.Object(args[2]);
Memory.readByteArray(data.bytes(), data.length());

遍历NSArray
var array = new ObjC.Object(args[2]);

 * Be sure to use valueOf() as NSUInteger is a Number in
 * 32-bit processes, and UInt64 in 64-bit processes. This
 * coerces it into a Number in the latter case.

var count = array.count().valueOf();
for (var i = 0; i !== count; i++) {
    var element = array.objectAtIndex_(i);
}

遍历NSDictionary
var dict = new ObjC.Object(args[2]);
var enumerator = dict.keyEnumerator();
var key;
while ((key = enumerator.nextObject()) !== null) {
  var value = dict.objectForKey_(key);
}

NSKeyedArchiver
var parsedValue = ObjC.classes.NSKeyedUnarchiver.unarchiveObjectWithData_(value);

读一个结构体
Memory.readU32(args[0].add(4));

模块基址
0x103a71690 comic-universal!0x2d69690
也可以用0x103a71690-0x2d69690获得

var moduleName = "comic-universal";
console.log("\n" + "base : " + Module.findBaseAddress(moduleName));

枚举所有的类
for (var className in ObjC.classes)
    {
        if (ObjC.classes.hasOwnProperty(className))
        {
            send(className);
        }
}


枚举一个类的所有method
if (ObjC.available)
{
    try
    {
        var className = "NSURL";
        var methods = eval('ObjC.classes.' + className + '.$methods');
        for (var i = 0; i < methods.length; i++)
        {
            try
            {
                if (methods[i].indexOf("fileURLWithPath") > -1)
                console.log("[-] "+methods[i]);
            }
            catch(err)
            {
                console.log("[!] Exception1: " + err.message);
            }
        }
    }
    catch(err)
    {
        console.log("[!] Exception2: " + err.message);
    }
}


 */
export const ocTestClass = () => {
    let _className = "JDxxxInfo";
    let _methodName = "+ xxxxbreak";
    let hooking = ObjC.classes[_className][_methodName]
    KaiLog.log(`Class className is: ${_className} methodName is: ${_methodName}`)
    Interceptor.attach(hooking.implemention, {
        onEnter(args) {
            // args[0]: self ?
            // args[1]: The selector
            // args[2] 第一个参数
            KaiLog.log(`oc method onEnter, args=${args}`);
            let tmpClassName = new ObjC.Object(args[0]).toString();
            let tmpMethodName = ObjC.selectorAsString(args[1]);
            let tmpParam0 = new ObjC.Object(args[2]);
            let tmpParam0Str = tmpParam0.toString();
            let tmpParam0Type = tmpParam0.$className; // 看变量类型
            KaiLog.log(`tmpClassName=${tmpClassName} methodName=${tmpMethodName} tmpParam0=${tmpParam0Str} type=${tmpParam0Type}`);
            let backtraceList = Thread.backtrace(this.context, Backtracer.ACCURATE);
            let newBacktraceList = backtraceList.map(DebugSymbol.fromAddress);
            let tmpStr = newBacktraceList.join("\n\t");
            KaiLog.log(`called from:\n${tmpStr}`);
        },
        onLeave(returnValue) {
            KaiLog.log(`oc method onLeave, returnValue=${returnValue}`);
            let typeValue = Object.prototype.toString.call(returnValue);
            let typeValue2 = returnValue.toString();
            let xx = new ObjC.Object(returnValue);
            var newRet = ObjC.classes.NSString.stringWithString_("1");
            returnValue.replace(newRet);
            KaiLog.log(`new Return Value: ${returnValue}`);
        }
    });
}

export const ocTestInstance = () => {
    let _className = "JDxxxInfo";
    let _methodName = "- setXxx:";
    // let hookingClass = ObjC.chooseSync(ObjC.classes[_className])[0]; // 存在实例
    let hookingClass = ObjC.classes[_className].alloc();
    let hooking = hookingClass[_methodName]
    KaiLog.log(`Instance className is: ${_className} methodName is: ${_methodName}`)
    Interceptor.attach(hooking.implemention, {
        onEnter(args) {
            // args[0]: self
            // args[1]: The selector
            // args[2] 第一个参数
            KaiLog.log(`instance oc method onEnter, args=${args}`);
            let tmpClassName = new ObjC.Object(args[0]).toString();
            let tmpMethodName = ObjC.selectorAsString(args[1]);
            let tmpParam0 = new ObjC.Object(args[2]).toString();
            KaiLog.log(`instance  tmpClassName=${tmpClassName} methodName=${tmpMethodName} tmpParam0=${tmpParam0}`);
            let backtraceList = Thread.backtrace(this.context, Backtracer.ACCURATE);
            let newBacktraceList = backtraceList.map(DebugSymbol.fromAddress);
            let tmpStr = newBacktraceList.join("\n");
            KaiLog.log(`instance  called from:\n${tmpStr}`);
        },
        onLeave(returnValue) {
            KaiLog.log(`instance oc method onLeave, returnValue=${returnValue}`);
            let typeValue = Object.prototype.toString.call(returnValue);
            let typeValue2 = returnValue.toString();
            let xx = new ObjC.Object(returnValue);
            var newRet = ObjC.classes.NSString.stringWithString_("1");
            // newretval = ptr("0x0")
            returnValue.replace(newRet);
            KaiLog.log(`instance new Return Value: ${returnValue}`);
        }
    });
}

export const ocInvokeFunction = () => {
    // let address = Module.findExportByName('libsqlite3.dylib', 'sqlite3_sql');
    // let sql = new NativeFunction(address, 'char', ['pointer']);
    // sql(statement);
}