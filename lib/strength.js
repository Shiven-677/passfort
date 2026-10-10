/*
 * PassFort - local password strength estimator
 *
 * PRIVACY: runs entirely in memory. No network calls, no storage,
 * and the password is never logged. Do NOT add console.log(password).
 *
 * HOW IT WORKS (simplified model, easy to explain):
 *   1. Find predictable parts of the password (common words, repeats,
 *      sequences, keyboard runs, years) and mark those characters "covered".
 *   2. Covered characters add ~0 bits; every other character adds
 *      log2(pool size) bits, where pool = characters an attacker must try.
 *   3. Turn the total bits into a 1-4 score, then apply length caps.
 *
 * Loaded as a classic script so it works in the popup and as a content script.
 */
(function () {
    'use strict';

    const GUESSES_PER_SECOND = 1e10;   // fast offline attack on a weak hash
    const MAX_ANALYZE = 256;           // keeps pattern checks fast on huge pastes
    const LABELS = ['', 'Weak', 'Fair', 'Good', 'Strong'];

    const COMMON_PASSWORDS = [
        'password', 'passw0rd', 'password1', 'password123', '123456', '1234567',
        '12345678', '123456789', '1234567890', '12345', '111111', '000000',
        '654321', '123123', '121212', '1q2w3e4r', '1qaz2wsx', 'qazwsx',
        'zaq12wsx', 'qwerty', 'qwerty123', 'qwertyuiop', 'asdfgh', 'abc123',
        'iloveyou', 'admin', 'admin123', 'root', 'toor', 'test', 'guest',
        'default', 'changeme', 'welcome', 'welcome123', 'login', 'letmein',
        'monkey', 'dragon', 'master', 'shadow', 'sunshine', 'princess',
        'superman', 'batman', 'starwars', 'football', 'baseball', 'soccer',
        'hockey', 'cricket', 'hello', 'freedom', 'whatever', 'trustno1',
        'secret', 'summer', 'winter', 'flower', 'mustang', 'computer',
        'internet', 'cheese', 'pepper', 'killer', 'hunter', 'ranger',
        'harley', 'buster', 'tigger', 'access', 'michael', 'jordan', 'jessica',
        'jennifer', 'ashley', 'daniel', 'robert', 'thomas', 'charlie', 'andrew',
        'george', 'michelle', 'india', 'india123', 'mumbai', 'krishna',
        'ganesh', 'discord', 'google', 'facebook', 'instagram', 'netflix',
        'minecraft', 'pokemon', 'naruto', 'love', 'sex', 'god'
    ];

    const KEYBOARD_ROWS = [
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx3edc', 'qazwsxedc'
    ];
    // also catch them typed backwards
    const KEYBOARD_PATTERNS = KEYBOARD_ROWS.concat(
        KEYBOARD_ROWS.map((row) => row.split('').reverse().join(''))
    );

    // "Leetspeak" substitutions, so p@ssw0rd is treated like password
    const LEET = {
        '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i',
        '0': 'o', '$': 's', '5': 's', '7': 't'
    };

    // Same length as the input, so character positions line up.
    function normalize(str) {
        let out = '';
        for (let i = 0; i < str.length; i++) {
            const c = str[i];
            const lower = c.toLowerCase();
            out += LEET[c] || (lower.length === 1 ? lower : c);
        }
        return out;
    }

    // Normalize the list once so both sides use the same rules.
    const COMMON_SET = new Set(COMMON_PASSWORDS.map(normalize));
    const COMMON_SUBSTRINGS = [...COMMON_SET].filter((w) => w.length >= 5);

    // Turn names/emails/usernames from the same form into search tokens.
    // "john.smith92@mail.com" -> johnsmith92, john, smith92, smith (domain ignored)
    function personalTokens(info) {
        const tokens = new Set();
        if (!Array.isArray(info)) return [];
        const add = (t) => { if (t.length >= 3) tokens.add(normalize(t)); };

        for (const raw of info.slice(0, 10)) {
            if (typeof raw !== 'string') continue;
            let text = raw.toLowerCase().trim().slice(0, 100);
            if (text.includes('@')) text = text.split('@')[0];      // drop email domain
            add(text.replace(/[\s._+\-]+/g, ''));                    // whole value, no separators
            for (const part of text.split(/[\s._+\-]+/)) {
                add(part);
                add(part.replace(/[0-9]+/g, ''));                      // "smith92" -> "smith"
            }
        }
        return [...tokens].slice(0, 30);
    }

    // How many different characters an attacker must try per position.
    function poolSize(pw) {
        let pool = 0;
        if (/[a-z]/.test(pw)) pool += 26;
        if (/[A-Z]/.test(pw)) pool += 26;
        if (/[0-9]/.test(pw)) pool += 10;
        if (/[ -\/:-@\[-`{-~]/.test(pw)) pool += 33;   // ASCII symbols + space
        if (/[^\x00-\x7F]/.test(pw)) pool += 100;      // rough guess for Unicode
        return pool || 1;
    }

    function formatCrackTime(bits) {
        // On average an attacker finds it after trying half the possibilities.
        const seconds = Math.pow(2, Math.max(bits - 1, 0)) / GUESSES_PER_SECOND;
        const MIN = 60, HOUR = 3600, DAY = 86400, YEAR = 31557600;
        if (seconds < 1) return 'less than a second';
        if (seconds < MIN) return Math.round(seconds) + ' seconds';
        if (seconds < HOUR) return Math.round(seconds / MIN) + ' minutes';
        if (seconds < DAY) return Math.round(seconds / HOUR) + ' hours';
        if (seconds < YEAR) return Math.round(seconds / DAY) + ' days';
        const years = seconds / YEAR;
        if (years < 1000) return Math.round(years) + ' years';
        if (years < 1e6) return 'thousands of years';
        if (years < 1e9) return 'millions of years';
        return 'billions of years or more';
    }

    function emptyResult() {
        return {
            score: 0, label: 'Enter a password', bits: 0,
            crackTime: '', feedback: [], length: 0
        };
    }

    function assess(input, personalInfo) {
        if (typeof input !== 'string' || input.length === 0) return emptyResult();

        const length = input.length;
        const pw = input.slice(0, MAX_ANALYZE);
        const lower = pw.toLowerCase();
        const norm = normalize(pw);

        const covered = new Array(pw.length).fill(false);
        const found = {
            commonExact: false, common: false, personal: false, repeat: false,
            block: false, sequence: false, keyboard: false, year: false
        };

        function mark(from, to) {
            for (let i = from; i < to && i < covered.length; i++) covered[i] = true;
        }

        // 1) Common passwords / words
        if (COMMON_SET.has(norm)) {
            found.commonExact = true;
            mark(0, pw.length);
        } else {
            for (const word of COMMON_SUBSTRINGS) {
                let idx = norm.indexOf(word);
                while (idx !== -1) {
                    found.common = true;
                    mark(idx, idx + word.length);
                    idx = norm.indexOf(word, idx + 1);
                }
            }
        }
        // 1b) Parts of the user's own name / username / email
        for (const token of personalTokens(personalInfo)) {
            if (!token) continue;
            let idx = norm.indexOf(token);
            while (idx !== -1) {
                found.personal = true;
                mark(idx, idx + token.length);
                idx = norm.indexOf(token, idx + 1);
            }
        }

        // 2) Repeated characters: aaa, 1111
        const runRe = /(.)\1{2,}/gi;
        let m;
        while ((m = runRe.exec(pw)) !== null) {
            found.repeat = true;
            mark(m.index + 1, m.index + m[0].length);
        }

        // 3) Repeated blocks: abab, abcabc
        const blockRe = /(.{2,}?)\1+/gi;
        while ((m = blockRe.exec(pw)) !== null) {
            const block = m[1];
            if (new Set(block.toLowerCase()).size > 1) found.block = true;
            mark(m.index + block.length, m.index + m[0].length);
        }

        // 4) Sequences: abc, 123, cba, 321 (letters and digits only)
        const isAlnum = (c) => /[a-z0-9]/.test(c);
        let i = 0;
        while (i < lower.length - 2) {
            const step = lower.charCodeAt(i + 1) - lower.charCodeAt(i);
            if ((step === 1 || step === -1) && isAlnum(lower[i]) && isAlnum(lower[i + 1])) {
                let j = i + 1;
                while (j + 1 < lower.length &&
                    lower.charCodeAt(j + 1) - lower.charCodeAt(j) === step &&
                    isAlnum(lower[j + 1])) {
                    j++;
                }
                if (j - i + 1 >= 3) {
                    found.sequence = true;
                    mark(i + 1, j + 1);
                    i = j;
                    continue;
                }
            }
            i++;
        }

        // 5) Keyboard patterns: qwer, asdf, zxcv (any 4-letter window)
        for (const pattern of KEYBOARD_PATTERNS) {
            for (let k = 0; k + 4 <= lower.length; k++) {
                if (pattern.includes(lower.slice(k, k + 4))) {
                    found.keyboard = true;
                    mark(k + 1, k + 4);
                }
            }
        }

        // 6) Years: 1987, 2024 (only ~100 possibilities, so mostly predictable)
        const yearRe = /(?:19|20)\d{2}/g;
        while ((m = yearRe.exec(pw)) !== null) {
            found.year = true;
            mark(m.index + 2, m.index + 4);
        }

        // Entropy from the characters that are NOT predictable
        const unpredictable = covered.filter((c) => !c).length;
        const bits = unpredictable * Math.log2(poolSize(pw));

        // Score, then length caps (length matters most)
        let score = bits < 36 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
        if (length < 8) score = Math.min(score, 1);
        else if (length < 12) score = Math.min(score, 3);
        if (found.commonExact) score = 1;
        if (found.personal) score = Math.min(score, 2);   // using your own details is a classic weakness

        // Human-readable feedback
        const feedback = [];
        if (length < 8) feedback.push('Too short. Use at least 12 characters.');
        else if (length < 12) feedback.push('Longer is stronger. Aim for 12 or more characters.');
        if (found.commonExact) feedback.push('This is one of the most commonly used passwords.');
        else if (found.common) feedback.push('Contains a very common password or word.');
        if (found.personal) feedback.push('Contains part of your name, username or email. Attackers try these first.');
        if (found.repeat) feedback.push("Avoid repeated characters like 'aaa' or '111'.");
        if (found.block) feedback.push("Avoid repeated chunks like 'abab' or 'abcabc'.");
        if (found.sequence) feedback.push("Avoid sequences like 'abc' or '1234'.");
        if (found.keyboard) feedback.push("Avoid keyboard patterns like 'qwer' or 'asdf'.");
        if (found.year) feedback.push('Years and dates are easy for attackers to guess.');
        if (score < 3) {
            if (/^[0-9]+$/.test(pw)) feedback.push('Numbers only. Add letters and symbols.');
            else if (/^[a-zA-Z]+$/.test(pw)) feedback.push('Letters only. Add numbers or symbols.');
        }
        if (feedback.length === 0) {
            if (score === 4) feedback.push('Excellent. Use it for one account only.');
            else if (score === 3) feedback.push('Good. A few more characters would make it stronger.');
            else feedback.push('Add more characters or mix character types.');
        }

        return {
            score,
            label: LABELS[score],
            bits: Math.round(bits),
            crackTime: formatCrackTime(bits),
            feedback,
            length
        };
    }

    const root = typeof globalThis !== 'undefined' ? globalThis : window;
    root.PassFort = root.PassFort || {};
    root.PassFort.strength = { assess, LABELS };
})();