# StegCloak Web Reveal

This is a quick POC of a script to inject to reveal detected hidden secrets in a web page using [StegCloak](https://github.com/KuroLabs/stegcloak).

The message can't be too big, so the script can't scan the whole page. Hence, it needs to search in more specific selectors.

So as an example, this example works with Discord messages (web version).

![example](example.png)

## How it works

- All the Discord messages are found (selector `div[class*='messageContent-']"`)
- We only keep those which are not revealed yet and which contain invisible characters
- We replace the text in the messages

It uses [browserify](http://browserify.org/) to create a single script to inject in the browser.

To inject the script, you have multiple extensions available for every browser. So, just choose one, and inject the script in the web page.