/*
 * PassFort - secure password generator
 *
 * Uses crypto.getRandomValues (Web Crypto), never Math.random().
 * Nothing is stored or sent anywhere. Do NOT add console.log(password).
 *
 * Classic script (not an ES module) to match lib/strength.js.
 */
(function () {
    'use strict';

    const SETS = {
        lower: 'abcdefghijklmnopqrstuvwxyz',
        upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        numbers: '0123456789',
        symbols: '!@#$%^&*()-_=+[]{}:;,.?/~'
    };
    const AMBIGUOUS = 'O0Il1';       // look-alike characters
    const MIN_LENGTH = 8;
    const MAX_LENGTH = 64;

    // Uniform random integer in [0, max). Rejection sampling avoids modulo bias.
    function randomInt(max) {
        const RANGE = 0x100000000;                 // 2^32 possible Uint32 values
        const limit = RANGE - (RANGE % max);       // largest unbiased multiple of max
        const buf = new Uint32Array(1);
        do {
            crypto.getRandomValues(buf);
        } while (buf[0] >= limit);                 // discard values in the uneven tail
        return buf[0] % max;
    }

    function pickFrom(chars) {
        return chars[randomInt(chars.length)];
    }

    // Fisher-Yates shuffle using the secure random source
    function shuffle(array) {
        for (let i = array.length - 1; i > 0; i--) {
            const j = randomInt(i + 1);
            [array[i], array[j]] = [array[j], array[i]];
        }
        return array;
    }

    function generate(options) {
        const opts = Object.assign(
            { length: 16, lower: true, upper: true, numbers: true, symbols: true, avoidAmbiguous: false },
            options
        );

        const length = Math.floor(Number(opts.length));
        if (!Number.isFinite(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
            throw new Error(`Length must be between ${MIN_LENGTH} and ${MAX_LENGTH}.`);
        }

        // Build one pool per selected type (optionally without look-alikes)
        const pools = [];
        for (const type of ['lower', 'upper', 'numbers', 'symbols']) {
            if (!opts[type]) continue;
            let chars = SETS[type];
            if (opts.avoidAmbiguous) {
                chars = [...chars].filter((c) => !AMBIGUOUS.includes(c)).join('');
            }
            if (chars.length > 0) pools.push(chars);
        }
        if (pools.length === 0) {
            throw new Error('Select at least one character type.');
        }

        const combined = pools.join('');
        const result = [];

        // 1) guarantee at least one character from every selected type
        pools.forEach((pool) => result.push(pickFrom(pool)));
        // 2) fill the rest from the combined pool
        while (result.length < length) result.push(pickFrom(combined));
        // 3) shuffle so the guaranteed characters aren't always first
        shuffle(result);

        return {
            password: result.join(''),
            bits: Math.round(length * Math.log2(combined.length))   // approximate entropy
        };
    }

    const root = typeof globalThis !== 'undefined' ? globalThis : window;
    root.PassFort = root.PassFort || {};
    root.PassFort.generator = { generate, MIN_LENGTH, MAX_LENGTH };
})();