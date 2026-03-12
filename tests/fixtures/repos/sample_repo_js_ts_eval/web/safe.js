// JS file with NO security issues — should produce zero findings
function safeParse(data) {
    return JSON.parse(data);
}

const result = safeParse('{"key": "value"}');
console.log(result);
