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