var greeting = "\x68\x65\x6c\x6c\x6f";
var target = '\u0077\u006f\u0072\u006c\u0064';
var face = "\uD83D\uDE00";
var quoted = "\x22\x5c\x22";
var control = "\x00\x1b[31m";
var mixed = "tab\there \x41";
console.log(greeting, target, face, quoted, control.length, mixed);
