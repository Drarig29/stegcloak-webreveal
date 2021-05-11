const StegCloak = require('stegcloak');

console.log('Loading reveal.js');

const containsInvisible = text => text.match(RegExp(StegCloak.zwc.join('|')));

const stegCloak = new StegCloak(true, false);
const messages = Array.from(document.querySelectorAll("div[class*='messageContent-']")).filter(el => containsInvisible(el.innerText));
const revealed = messages.map(el => `${el.innerText} --> ${stegCloak.reveal(el.innerText, 'pass')}`);

console.log({ revealed });