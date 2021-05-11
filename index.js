const StegCloak = require('stegcloak');

const password = 'pass';
const revealedIdentifier = '<strong>[Revealed]</strong>';

const containsInvisible = text => text.match(RegExp(StegCloak.zwc.join('|')));
const isRevealed = text => text.indexOf(revealedIdentifier) !== -1;
const hide = text => `<s>${text}</s>`;
const reveal = text => stegCloak.reveal(text, password);

console.log('Loading reveal.js');

const stegCloak = new StegCloak(true, false);
const elements = Array.from(document.querySelectorAll("div[class*='messageContent-']"));
const encrypted = elements.filter(el => containsInvisible(el.innerText) && !isRevealed(el.innerHTML));

encrypted.forEach(el => el.innerHTML = `${revealedIdentifier} ${hide(el.innerText)} ${reveal(el.innerText)}`);

if (encrypted.length) {
    alert(`${encrypted.length} messages were revealed!`);
} else {
    alert('No message to reveal.');
}