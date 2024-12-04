import Swift from '../index2.js'
import { doSthEntry } from "./test_sth.js";


console.log('\n\n\n');
console.log('Kai Script loaded successfully2.');
console.log(`Process.arch=${Process.arch}`); // arm x64

console.log(`ObjC.available=${ObjC.available}`)
console.log(`Swift.available=${Swift.available}`)

/*
export const doSthEntry = () => {

}
 */
doSthEntry();
