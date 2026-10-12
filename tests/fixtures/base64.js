var endpoint = atob("aHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20vdjEvdXNlcnM=");
var word = String.fromCharCode(0x68, 0x69, 33);
var smile = String.fromCodePoint(128512);
var binary = atob("AAH/");
var dynamic = atob(window.payload || "");
console.log(endpoint, word, smile, binary.length, dynamic);
