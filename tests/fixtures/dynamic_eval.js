var result = eval("1 + 1");
var build = new Function("a", "b", "return a + b");
var indirect = Function("return this")();
setTimeout("tick()", 1000);
setInterval(function () { tick(); }, 1000);
var escape = (function () {}).constructor("return globalThis")();
var evalReference = eval;
