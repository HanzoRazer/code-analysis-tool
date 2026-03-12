// JS file that triggers ALL four rules.

// SEC_EVAL_JS_001: eval() call
eval("alert('xss')");

// SEC_NEW_FUNCTION_JS_001: new Function()
const fn = new Function("return 42");

// EXC_EMPTY_CATCH_JS_001: empty catch block
try {
    riskyOperation();
} catch (e) {
}

// GST_GLOBAL_THIS_MUTATION_001: globalThis mutation
globalThis.myGlobal = "polluted";

// SEC_DYNAMIC_MODULE_LOAD_JS_001
const m = "./" + "x";
require(m);
