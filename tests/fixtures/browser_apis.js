var agent = navigator.userAgent;
document.cookie = "seen=1; path=/";
var jar = document.cookie.split(";");
window.localStorage.setItem("theme", "dark");
var theme = sessionStorage["getItem"]("theme");
var request = new XMLHttpRequest();
var socket = new WebSocket("wss://live.example.com/feed");
navigator.sendBeacon("/beacon", agent);
var canvas = document.createElement("canvas");
var gl = canvas.getContext("webgl");
var flat = canvas.getContext("2d");
var picture = canvas.toDataURL();
var audio = new AudioContext();
var oscillator = audio.createOscillator();
var peer = new RTCPeerConnection({ iceServers: [] });
navigator.mediaDevices.getUserMedia({ audio: true });
var later = fetch;
function isolated(document) {
  return document.title;
}
