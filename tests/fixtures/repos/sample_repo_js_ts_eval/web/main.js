// JS file with eval() — should trigger SEC_EVAL_JS_001
const userInput = "alert('xss')";
eval(userInput);

function processData(data) {
    return eval("(" + data + ")");
}
