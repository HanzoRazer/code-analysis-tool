// Negative test: no rules should trigger here.

function safeFunction() {
    const data = JSON.parse('{}');
    try {
        doSomething(data);
    } catch (err) {
        console.error("Error:", err.message);
    }
    const localVar = 42;
    return localVar;
}

// This is NOT eval — it's a function called "evaluate"
function evaluate(expr) {
    return expr + 1;
}
