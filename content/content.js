/*
 * PassFort - in-page strength meter (content script)
 *
 * Injected ONLY when the user clicks "Activate on this page" in the popup.
 * Shows a floating meter under password fields while the user types.
 *
 * PRIVACY / SECURITY:
 *  - The password is read only inside update(), analysed in memory, and dropped.
 *  - No messaging, storage, network, or logging of the password.
 *  - UI lives in a CLOSED shadow root, so page scripts can't read or restyle it.
 *  - Built with createElement + textContent only (no innerHTML).
 */
(function () {
    'use strict';

    if (window.__passfortActive) return;          // already running on this page
    if (!globalThis.PassFort || !globalThis.PassFort.strength) return;
    window.__passfortActive = true;

    const { assess } = globalThis.PassFort.strength;

    // ---------- Styles (inside the shadow root) ----------
    const CSS = `
    :host { all: initial; }
    .panel {
      position: fixed; box-sizing: border-box; width: 280px; padding: 10px 12px;
      background: #0b1220; color: #e6edf7;
      border: 1px solid #22304d; border-radius: 10px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
      font: 13px/1.4 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      pointer-events: none;
    }
    .panel[hidden] { display: none; }
    .head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .brand { font-weight: 700; font-size: 12px; letter-spacing: 0.3px; color: #22d3ee; }
    .label { font-weight: 700; }
    .meter { display: flex; gap: 4px; }
    .seg { flex: 1; height: 6px; border-radius: 3px; background: #22304d; }
    .panel[data-level="1"] .seg:nth-child(-n+1) { background: #ef4444; }
    .panel[data-level="2"] .seg:nth-child(-n+2) { background: #f59e0b; }
    .panel[data-level="3"] .seg:nth-child(-n+3) { background: #84cc16; }
    .panel[data-level="4"] .seg:nth-child(-n+4) { background: #22c55e; }
    .panel[data-level="1"] .label { color: #ef4444; }
    .panel[data-level="2"] .label { color: #f59e0b; }
    .panel[data-level="3"] .label { color: #84cc16; }
    .panel[data-level="4"] .label { color: #22c55e; }
    .detail { margin-top: 6px; font-size: 11px; color: #93a4c0; }
    .tips { margin: 8px 0 0; padding-left: 16px; font-size: 12px; color: #93a4c0; }
    .tips li { margin-bottom: 2px; }
  `;

    // Constructed stylesheets are not blocked by a site's CSP (inline <style> can be).
    function applyStyles(shadow) {
        try {
            const sheet = new CSSStyleSheet();
            sheet.replaceSync(CSS);
            shadow.adoptedStyleSheets = [sheet];
        } catch (err) {
            const style = document.createElement('style');
            style.textContent = CSS;
            shadow.appendChild(style);
        }
    }

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text) node.textContent = text;
        return node;
    }

    // ---------- Build the UI once ----------
    const host = document.createElement('div');
    Object.assign(host.style, {
        position: 'fixed', top: '0', left: '0', width: '0', height: '0',
        zIndex: '2147483647', pointerEvents: 'none'
    });
    const shadow = host.attachShadow({ mode: 'closed' });
    applyStyles(shadow);

    const panel = el('div', 'panel');
    panel.hidden = true;

    const labelEl = el('span', 'label');
    labelEl.setAttribute('aria-live', 'polite');
    const head = el('div', 'head');
    head.append(el('span', 'brand', 'PassFort'), labelEl);

    const meter = el('div', 'meter');
    meter.setAttribute('aria-hidden', 'true');
    for (let i = 0; i < 4; i++) meter.appendChild(el('span', 'seg'));

    const detailEl = el('div', 'detail');
    const tipsEl = el('ul', 'tips');

    panel.append(head, meter, detailEl, tipsEl);
    shadow.appendChild(panel);
    document.documentElement.appendChild(host);

    // ---------- Behaviour ----------
    let activeField = null;

    function isPasswordInput(node) {
        return node instanceof HTMLInputElement && node.type === 'password';
    }

    function render(result) {
        panel.dataset.level = String(result.score);
        if (labelEl.textContent !== result.label) labelEl.textContent = result.label;
        detailEl.textContent = result.score
            ? `${result.bits} bits · crack time ≈ ${result.crackTime}`
            : 'Start typing to check strength';
        tipsEl.replaceChildren(
            ...result.feedback.slice(0, 3).map((text) => el('li', '', text))
        );
    }

    function place() {
        if (!activeField) return;
        if (!activeField.isConnected) { hide(); return; }
        const rect = activeField.getBoundingClientRect();
        if (rect.width === 0 && rect.height === 0) { panel.hidden = true; return; }

        panel.hidden = false;
        const margin = 8;
        const left = Math.min(Math.max(margin, rect.left),
            window.innerWidth - panel.offsetWidth - margin);
        let top = rect.bottom + 6;
        // not enough room below the field? show above it instead
        if (top + panel.offsetHeight > window.innerHeight - margin &&
            rect.top - panel.offsetHeight - 6 > margin) {
            top = rect.top - panel.offsetHeight - 6;
        }
        panel.style.left = left + 'px';
        panel.style.top = top + 'px';
    }

    function update() {
        if (!activeField || !activeField.isConnected) { hide(); return; }
        render(assess(activeField.value));   // value is used here and not kept
        place();
    }

    function hide() {
        activeField = null;
        panel.hidden = true;
    }

    let placeQueued = false;
    function schedulePlace() {
        if (placeQueued) return;
        placeQueued = true;
        requestAnimationFrame(() => { placeQueued = false; place(); });
    }

    // Event delegation on document: also covers fields the site adds later (SPAs)
    document.addEventListener('focusin', (e) => {
        if (isPasswordInput(e.target)) { activeField = e.target; update(); }
    }, true);

    document.addEventListener('input', (e) => {
        if (e.target === activeField) update();
    }, true);

    document.addEventListener('focusout', (e) => {
        if (e.target !== activeField) return;
        if (isPasswordInput(e.relatedTarget)) return;   // moving to another password field
        hide();
    }, true);

    window.addEventListener('scroll', schedulePlace, true);
    window.addEventListener('resize', schedulePlace);

    // If a password field already has focus when activated, show the meter now
    if (isPasswordInput(document.activeElement)) {
        activeField = document.activeElement;
        update();
    }
})();


