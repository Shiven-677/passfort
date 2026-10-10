# PassFort

PassFort is a privacy-first password security tool built as a Chrome extension (Manifest V3) for a college cybersecurity project. It uses plain HTML, CSS and JavaScript, with no backend, no database, no paid API, no frameworks and no build tools. It never stores passwords.

## What it does

Password strength checker. As you type, the popup shows a four-level meter (Weak, Fair, Good, Strong), an entropy estimate, and tips about length, common passwords, repeated characters, sequences, keyboard patterns and years. The estimator was written for this project and runs entirely on your device.

Password generator. Choose a length from 8 to 64 and the character types you want. Passwords are generated with crypto.getRandomValues, always include at least one character of every selected type, and can be copied or regenerated. PassFort does not save them, so keep them somewhere safe.

In-page meter. Click the PassFort icon and press "Activate on this page", and a small panel appears under password fields on that tab. It shows the live strength, warns when the page or the form uses insecure HTTP, and warns when the password contains part of the name, username or email typed in the same form.

Breach check. In the popup, "Check if breached" looks the password up in the Have I Been Pwned database using k-anonymity. The password is hashed on your device with SHA-1, only the first five characters of the hash are sent, and the match is made locally. It runs only when you click the button.

## Security design

Permissions are limited to activeTab and scripting. Nothing runs on a page until the user clicks Activate, and that access ends when the tab is closed or navigated away.

The script injected into web pages is kept deliberately small: it has no network access, no messaging and no storage. The only network request in the whole extension is the breach lookup, which is made from the popup, to a single host, after a button click.

The extension's content security policy allows only its own scripts and limits connections to api.pwnedpasswords.com. The in-page panel lives in a closed shadow DOM and is built with textContent, never innerHTML. Passwords are never stored or logged.

## Installation

1. Clone the repository, or download it as a ZIP and extract it.
2. Open chrome://extensions and turn on Developer mode.
3. Click Load unpacked and select the folder that contains manifest.json.
4. Pin PassFort from the puzzle-piece menu.
5. After changing any file, press the reload icon on the PassFort card.

## Testing

Strength checker: type password, qwerty12345, aaaaaaaaaaaa and Tr1cky-Giraffe-Lamp-92. The first three should be Weak with relevant tips and the last should be Strong.

Generator: the password length should match the slider, unticking every character type should show an error and disable Copy, look-alike characters should never appear when that option is on, and the pasted text should match what was copied.

Breach check: the word password should be reported as seen many times, and a long random password should not be found. With Wi-Fi off, a clear error message should appear instead of a crash.

In-page meter: run "python -m http.server 8000" in the project folder, open localhost:8000/test/test-page.html, and activate. The panel should follow the password field, the insecure-form warning should appear, and a password containing the typed name or email should be capped at Fair.

## Limitations

The website can already read what is typed into its own fields, so PassFort adds no new exposure but cannot hide it from the page. A "not found" breach result does not mean a password is safe. The estimator has no full dictionary, so passphrases made of ordinary words are scored mostly by length. The in-page panel covers the main page only and must be activated again after a full page reload.

## Future work

Dictionary-aware scoring with zxcvbn, a passphrase mode, clipboard auto-clear, and an in-page breach button backed by a dedicated, strictly validated background worker.
