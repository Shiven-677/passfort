/*
 * PassFort - optional breach check using the Have I Been Pwned
 * "Pwned Passwords" range API (k-anonymity).
 *
 * HOW IT STAYS PRIVATE:
 *   1. SHA-1 hash the password locally (Web Crypto).
 *   2. Send ONLY the first 5 hex characters of the hash.
 *   3. The server returns every breached hash suffix with that prefix.
 *   4. We compare the rest of our hash locally.
 * The password and the full hash never leave the device.
 *
 * SHA-1 is used only because the API is keyed on it; it protects nothing here.
 * This is the ONLY network request in PassFort, and it runs only on a click.
 */
(function () {
    'use strict';

    const API = 'https://api.pwnedpasswords.com/range/';
    const TIMEOUT_MS = 8000;
    // Optional: asks the API to pad responses so their size doesn't hint at the prefix.
    // A custom header triggers a CORS preflight, so enable only if it works in your browser.
    const ADD_PADDING = false;

    async function sha1Hex(text) {
        const data = new TextEncoder().encode(text);
        const digest = await crypto.subtle.digest('SHA-1', data);
        return Array.from(new Uint8Array(digest),
            (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    }

    async function checkBreach(password) {
        if (!password) throw new Error('Enter a password first.');

        const hash = await sha1Hex(password);
        const prefix = hash.slice(0, 5);    // the only part that is sent
        const suffix = hash.slice(5);       // stays on this device

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
        let response;
        try {
            response = await fetch(API + prefix, {
                method: 'GET',
                headers: ADD_PADDING ? { 'Add-Padding': 'true' } : {},
                credentials: 'omit',
                cache: 'no-store',
                referrerPolicy: 'no-referrer',
                signal: controller.signal
            });
        } finally {
            clearTimeout(timer);
        }

        if (!response.ok) {
            throw new Error('Breach service returned an error (' + response.status + ').');
        }

        const body = await response.text();
        for (const line of body.split('\n')) {
            const [candidate, count] = line.trim().split(':');
            if (candidate === suffix) {
                const n = parseInt(count, 10) || 0;
                if (n > 0) return { breached: true, count: n };   // padding entries have count 0
            }
        }
        return { breached: false, count: 0 };
    }

    const root = typeof globalThis !== 'undefined' ? globalThis : window;
    root.PassFort = root.PassFort || {};
    root.PassFort.breach = { checkBreach };
})();