// ---------- Tabs (keyboard accessible: Left/Right arrows) ----------
const tabs = [...document.querySelectorAll('[role="tab"]')];

function selectTab(selected) {
    tabs.forEach((tab) => {
        const active = tab === selected;
        tab.setAttribute('aria-selected', String(active));
        tab.tabIndex = active ? 0 : -1;
        document.getElementById(tab.getAttribute('aria-controls')).hidden = !active;
    });
}

tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => selectTab(tab));
    tab.addEventListener('keydown', (e) => {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
        const step = e.key === 'ArrowRight' ? 1 : tabs.length - 1;
        const next = tabs[(i + step) % tabs.length];
        selectTab(next);
        next.focus();
    });
});

// ---------- Feature 1: live strength checker ----------
const { assess } = PassFort.strength;

const passwordInput = document.getElementById('password-input');
const toggleBtn = document.getElementById('toggle-visibility');
const meter = document.getElementById('strength-meter');
const labelEl = document.getElementById('strength-label');
const detailEl = document.getElementById('strength-detail');
const feedbackList = document.getElementById('feedback-list');

function renderStrength(result) {
    meter.dataset.level = String(result.score);
    meter.setAttribute('aria-valuenow', String(result.score));
    meter.setAttribute('aria-valuetext', result.score ? result.label : 'No password entered');

    labelEl.textContent = result.label;
    labelEl.dataset.level = String(result.score);
    detailEl.textContent = result.score
        ? `${result.bits} bits · crack time ≈ ${result.crackTime}`
        : '';

    // textContent only (never innerHTML) so feedback can't inject markup
    feedbackList.replaceChildren(
        ...result.feedback.map((text) => {
            const li = document.createElement('li');
            li.textContent = text;
            return li;
        })
    );
}

passwordInput.addEventListener('input', () => {
    renderStrength(assess(passwordInput.value));
});

toggleBtn.addEventListener('click', () => {
    const reveal = passwordInput.type === 'password';
    passwordInput.type = reveal ? 'text' : 'password';
    toggleBtn.textContent = reveal ? 'Hide' : 'Show';
    toggleBtn.setAttribute('aria-pressed', String(reveal));
    toggleBtn.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
});

renderStrength(assess(''));

// ---------- In-page meter: activate on the current tab ----------
const activateBtn = document.getElementById('activate-btn');
const activateStatus = document.getElementById('activate-status');

activateBtn.addEventListener('click', async () => {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || tab.id === undefined) throw new Error('No active tab');

        await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ['lib/strength.js', 'content/content.js']
        });

        activateStatus.className = 'status';
        activateStatus.textContent = 'Active on this tab. Click into a password field.';
    } catch (err) {
        activateStatus.className = 'error';
        activateStatus.textContent =
            "Can't run on this page. Browser pages (chrome://), the Web Store and some PDFs are blocked.";
    }
});



// ---------- Feature 2: password generator ----------
const { generate } = PassFort.generator;

const generatedInput = document.getElementById('generated-password');
const copyBtn = document.getElementById('copy-btn');
const regenerateBtn = document.getElementById('regenerate-btn');
const copyStatus = document.getElementById('copy-status');
const entropyInfo = document.getElementById('entropy-info');
const lengthRange = document.getElementById('length-range');
const lengthValue = document.getElementById('length-value');
const generatorError = document.getElementById('generator-error');
const typeBoxes = ['opt-lower', 'opt-upper', 'opt-numbers', 'opt-symbols', 'opt-ambiguous']
    .map((id) => document.getElementById(id));

function readOptions() {
    return {
        length: Number(lengthRange.value),
        lower: document.getElementById('opt-lower').checked,
        upper: document.getElementById('opt-upper').checked,
        numbers: document.getElementById('opt-numbers').checked,
        symbols: document.getElementById('opt-symbols').checked,
        avoidAmbiguous: document.getElementById('opt-ambiguous').checked
    };
}

function refreshPassword() {
    copyStatus.textContent = '';
    try {
        const { password, bits } = generate(readOptions());
        generatedInput.value = password;
        entropyInfo.textContent = `≈ ${bits} bits of entropy`;
        generatorError.textContent = '';
        copyBtn.disabled = false;
    } catch (err) {
        // e.g. no character type selected
        generatedInput.value = '';
        entropyInfo.textContent = '';
        generatorError.textContent = err.message;
        copyBtn.disabled = true;
    }
}

lengthRange.addEventListener('input', () => {
    lengthValue.textContent = lengthRange.value;
    refreshPassword();
});
typeBoxes.forEach((box) => box.addEventListener('change', refreshPassword));
regenerateBtn.addEventListener('click', refreshPassword);

let copyTimer;
copyBtn.addEventListener('click', async () => {
    if (!generatedInput.value) return;
    let ok = true;
    try {
        await navigator.clipboard.writeText(generatedInput.value);
    } catch (err) {
        // fallback for older behaviour
        generatedInput.select();
        ok = document.execCommand('copy');
    }
    copyStatus.className = ok ? 'status' : 'error';
    copyStatus.textContent = ok
        ? 'Copied to clipboard.'
        : 'Copy failed. Select the text and press Ctrl+C.';
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => { copyStatus.textContent = ''; }, 2500);
});

refreshPassword();   // show a password as soon as the popup opens