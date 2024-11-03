import {KaiLog} from "../utils/kai_log.js";
import {KaiUtils} from "../utils/kai_utils.js";

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


 */

export const ocTestEntry = () => {
    let address = Module.findExportByName('libsqlite3.dylib', 'sqlite3_sql');
    KaiLog.log(`sqlite3_sql address=${address}`);
    if (address != null) {
        // var sql = new NativeFunction(address, 'char', ['pointer']);
        // sql(statement);
    }
}

const BlackClassPrefixList: string[] = ["_", "UI", "PU", "AK", "PS", "FLEX", "PU", "CN", "ZoomUI", "FLEX"
    , "PX", "Web", "PDF", "AX", "WML", "TRV", "FC", "Place", "WK", "PLL", "PX", "OB", "SL", "SL", "DOC", "SwiftUI"
    , "Object", "PK", "MK", "GL"];

const BlackMethodPrefixList: string[] = ["_", "safe","accessibility","setIsAccessibility","wml","wv","lks","flex","CA"
    ,"bs","px","ax","na","tbsf","sd","setSd","lks","setLks","lookin","CA","pep","cpl","CK","nu","ml","automation"
    , "setAccessibility", "storedAccessibility", "storedAccessibility", "indexOfAccessibility"]

export const lookOcModuleBaseAddress = () => {
    const moduleName = "KaiDemo";
    let baseAddress = Module.findBaseAddress(moduleName);
    KaiLog.log("oc module base : " + baseAddress);
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
    for (let className in ObjC.classes) {
        if (ObjC.classes.hasOwnProperty(className)) {
            // KaiLog.log(`enum className hasOwnProperty : ${className})`);
            if (className.endsWith('ViewController') && !KaiUtils.classHasCertPrefix(className, BlackClassPrefixList)) {
                KaiLog.log(`enum className has vc : ${className}`);
            }
        } else {
            KaiLog.log(`enum className noProperty : ${className}`);
        }
    }
}


export const ocTestClass = () => {
    let className = "NSURL";
    let funcName = "+ URLWithString:";
    let hooking = eval('ObjC.classes.' + className + '["' + funcName + '"]');
    KaiLog.log(`class hooking is: ${hooking}`);
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

export const objcApiResolverTest = () => {
    let resolver = new ApiResolver("objc");
    let matches = resolver.enumerateMatches('-[GCDTestViewController sellTicketEntry:]');
    for (let match of matches) {
        KaiLog.log(`matchName: ${match.name} address: ${match.address} size:${match.size}`)
        Interceptor.attach(match.address, {
            onEnter(args) {
                KaiLog.log(`apiResolver onEnter, args=${typeof args}`);
                // console.log(JSON.stringify(args))
                let arg0 = args[0]; // self
                console.log(`arg0: ${arg0}`);
                let arg1 = args[1]; //selector
                console.log(`arg1: ${arg1}`);
                let arg2 = args[2];
                console.log(`arg2: ${arg2}`);
                // let arg3 = args[3];
                // console.log(`arg3: ${arg3}`);
                // let arg4 = args[4];
                // console.log(`arg4: ${arg4}`);
                let classObj = new ObjC.Object(args[0]); // self
                KaiLog.log(`className=${classObj.$className} classObj: ${classObj}`);
                let methodName = args[1].readUtf8String(); // selector
                KaiLog.log(`methodName: ${methodName}`);
                let argInfo = new ObjC.Object(args[2]);
                KaiLog.log(`argInfo className=${argInfo.$className}: ${argInfo}`);
                let argToInt32 = argInfo.toString(); //NSNumber是bool时toInt32转换的内容不对
                KaiLog.log(`argToInt32=${argToInt32}`);
                if (argToInt32 === "0") {
                    let trueNumber = ObjC.classes.NSNumber.numberWithBool_(1);
                    args[2] = trueNumber;
                    KaiLog.log(`new argInfo className=${trueNumber.$className}: ${trueNumber}`);
                }
            },
            onLeave(returnValue) {
                KaiLog.log(`apiResolver onLeave, returnValue=${returnValue}`);
            }
        });
    }
}

export const lookOcClassMethod = (className: string): void => {
    let class1 = ObjC.classes[className];
    KaiLog.log(`target class is: ${class1}`);
    // let methods = class1.$methods;
    let methods = class1.$ownMethods;
    for (let method of methods) {
        if (!KaiUtils.methodHasCertPrefix(method, BlackMethodPrefixList)) {
            KaiLog.log(`look ${className} method: ${method}`);
        }
    }
    if (methods.length < 10) {
        let superClassName = class1.$superClass.$className;
        let superMethodList = class1.$superClass.$ownMethods;
        for (let method of superMethodList) {
            if (!KaiUtils.methodHasCertPrefix(method, BlackMethodPrefixList)) {
                KaiLog.log(`look ${superClassName} method: ${method}`);
            }
        }
    }
}

export const ocTestInstance = () => {
    // let _className = "JDxxxInfo";
    // let _methodName = "- setXxx:";
    // // let hookingClass = ObjC.chooseSync(ObjC.classes[_className])[0]; // 存在实例
    // let hookingClass = ObjC.classes[_className].alloc();
    // let hooking = hookingClass[_methodName]
    // KaiLog.log(`Instance className is: ${_className} methodName is: ${_methodName}`)
    let _className = "ZaTestListViewController";
    let _methodName = "- viewDidLoad";
    let class1 = ObjC.classes[_className];
    KaiLog.log(`target class is: ${class1}`);
    let methods = class1.$methods;
    for (let method of methods) {
        if (method.includes("combine") || (method.includes("view") && !KaiUtils.methodHasCertPrefix(method, BlackMethodPrefixList))) {
            KaiLog.log(`target method has view is: ${method}`);
        }
    }
    // var hooking = eval('ObjC.classes.' + _className + '["' + _methodName + '"]');
    let hook = class1[_methodName] // 不能分开写，比如先ObjC.classes[_className]给临时变量给读
    KaiLog.log(`class1 type=${typeof class1} hook=${typeof hook} imp=${hook.implementation}`);
    let hooking = ObjC.classes[_className][_methodName]
    KaiLog.log(`hooking type ${typeof hooking} is: ${hooking} imp=${hooking.implementation}`);
    // let hook2 = eval('ObjC.classes.' + _className + '["' + _methodName + '"]');
    // KaiLog.log(`hook2 is: ${hook2}`);
    Interceptor.attach(hooking.implementation, {
        onEnter(args) {
            // args[0]: self
            // args[1]: The selector
            // args[2] 第一个参数
            KaiLog.log(`instance oc method onEnter`);
            let tmpClassName = new ObjC.Object(args[0]).toString();
            let tmpMethodName = ObjC.selectorAsString(args[1]);
            // let tmpParam0 = new ObjC.Object(args[2]).toString();
            KaiLog.log(`instance  tmpClassName=${tmpClassName} methodName=${tmpMethodName}`);
            // KaiLog.log(`instance  tmpClassName=${tmpClassName} methodName=${tmpMethodName} tmpParam0=${tmpParam0}`);
            let backtraceList = Thread.backtrace(this.context, Backtracer.ACCURATE);
            let newBacktraceList = backtraceList.map(DebugSymbol.fromAddress);
            let tmpStr = newBacktraceList.join("\n");
            KaiLog.log(`instance called from:\n${tmpStr}`);
        },
        onLeave(returnValue) {
            KaiLog.log(`instance oc method onLeave, returnValue=${returnValue}`);
            // let typeValue = Object.prototype.toString.call(returnValue);
            // let typeValue2 = returnValue.toString();
            // let xx = new ObjC.Object(returnValue);
            // var newRet = ObjC.classes.NSString.stringWithString_("1");
            // // newretval = ptr("0x0")
            // returnValue.replace(newRet);
            KaiLog.log(`instance new Return Value: ${returnValue}`);
        }
    });
}

export const ocTestZaVcMethodInstance = () => {
    let hooking = ObjC.classes['ZaTestListViewController']['- combineSomeParam:number:'] //NSString int => NSString
    KaiLog.log(`hooking combineSomeParam type ${typeof hooking} is: ${hooking} imp=${hooking.implementation}`);
    Interceptor.attach(hooking.implementation, {
        onEnter(args) {
            KaiLog.log(`instance combineSomeParam method onEnter`);
            let tmpClassName = new ObjC.Object(args[0]).toString();
            let tmpMethodName = ObjC.selectorAsString(args[1]);
            let oriParam0 = new ObjC.Object(args[2]).toString();
            let oriParam1 = args[3].toInt32();

            args[2] =  ObjC.classes.NSString.stringWithString_("fei");
            // args[3].writeInt(oriParam1 + 1000); // access violation accessing
            // args[3] = ptr(oriParam1 + 1000); // access violation accessing
            args[3] = ptr(`${oriParam1 + 1000}`);
            KaiLog.log(`instance tmpClassName=${tmpClassName} methodName=${tmpMethodName} param0=${oriParam0} param1=${oriParam1}`);
        },
        onLeave(returnValue) {// NSString
            KaiLog.log(`instance oc method onLeave, returnValue=${returnValue}`);
            let returnObj = new ObjC.Object(returnValue)
            let newValue = returnObj + "_modified"
            let newNSString = ObjC.classes.NSString.stringWithString_(newValue);
            returnValue.replace(newNSString);
            // 数字应该是直接： returnValue.replace(1337) 或许也是数字字符串？
            KaiLog.log(`old returnObj is type: ${returnObj.$className} value=${returnObj}`) // 这里returnObj的值取到的也是被追加modified的
        }
    });
}

export const ocTestZaVcMethodInstance2 = () => {
    let hooking = ObjC.classes['ZaTestListViewController']['- combineObject:dic:array:'] //Student NSDictionary NSArray => NSDictionary
    KaiLog.log(`hooking combineObjectDicArray type ${typeof hooking} is: ${hooking} imp=${hooking.implementation}`);
    // #add的这个偏移是通过IDA的静态地址相减得到的
    // var avmpSignAddr = rpcV1SignAddr.add(0x1DCE);
    // console.log('avmpSignAddr: ' + avmpSignAddr);
    Interceptor.attach(hooking.implementation, {
        onEnter(args) {
            KaiLog.log(`instance combineObjectDicArray method onEnter`);
            let tmpClassName = new ObjC.Object(args[0]).toString();
            let tmpMethodName = ObjC.selectorAsString(args[1]);
            let stuObj = new ObjC.Object(args[2]);
            let dicObj = new ObjC.Object(args[3]);
            let arrayObj = new ObjC.Object(args[4]);
            stuObj.setName_("fei");
            let ivars = stuObj.$ivars;
            KaiLog.log(`ivars=${JSON.stringify(ivars)}`);
            let oriAge = stuObj.$ivars['_age'];
            let oriAge2 = stuObj.age(); // objc的属性调用方法
            KaiLog.log(`oriAge_${typeof oriAge}=${oriAge} oriAge2=${oriAge2}`)
            stuObj.setAge_(oriAge+ 100);

            let newMuDic = ObjC.classes.NSMutableDictionary.dictionaryWithDictionary_(dicObj);
            newMuDic.setObject_forKey_("newFridaValue", "newFridaKey");
            args[3] = newMuDic; //这样写，之前从args[3]创建的dicObj与这里的值不一样
            let oriKeyValue = newMuDic.objectForKey_('oriKey');
            let oriKeyValue2 = newMuDic.objectForKey_('oriKey2');

            let newMuArray = ObjC.classes.NSMutableArray.array();
            newMuArray.addObjectsFromArray_(arrayObj);
            newMuArray.addObject_("hello_From_frida");
            args[4] = newMuArray;

            KaiLog.log(`instance tmpClassName=${tmpClassName} methodName=${tmpMethodName}
             stuObj=${stuObj.$className}:${stuObj} dicObj=${dicObj.$className}:${dicObj}
              arrayObj=${arrayObj.$className}:${arrayObj} newMuDic=${newMuDic.$className}:${newMuDic}`);
            KaiLog.log(`dicValue1=${oriKeyValue.$className}:${oriKeyValue} value2=${oriKeyValue2.$className}:${oriKeyValue2} newMuArray=${newMuArray}`);
            KaiLog.log(`newArray count=${newMuArray.count()} newMuArray=${newMuArray} second=${newMuArray.objectAtIndex_(1)}`);
        },
        onLeave(returnValue) {// NSString
            KaiLog.log(`instance combineObjectDicArray onLeave, returnValue=${returnValue}`);
            let returnObj = new ObjC.Object(returnValue)
            returnObj.setObject_forKey_("directModifyValue", "directKey");
            KaiLog.log(`old returnObj is type: ${returnObj.$className} value=${returnObj}`) // 这里returnObj的值取到的也是被追加modified的
        }
    });
}

export const ocInvokeFunction = () => {
    // let address = Module.findExportByName('libsqlite3.dylib', 'sqlite3_sql');
    // let sql = new NativeFunction(address, 'char', ['pointer']);
    // sql(statement);
    let hooking = ObjC.classes['KaiStudent']['- giveSomething:']
    KaiLog.log(`hooking KaiStudent's fun type ${typeof hooking} is: ${hooking} imp=${hooking.implementation}`);
    let stuObj = ObjC.classes['KaiStudent'].new();
    stuObj.setName_("fridaName");
    stuObj.setAge_(666);
    stuObj.setNick_("fridaNickName");
    let resultObj = stuObj.giveSomething_("abc");
    KaiLog.log(`resultObj ${resultObj.$className}: ${resultObj}`);
}