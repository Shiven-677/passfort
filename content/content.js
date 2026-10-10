/*
 * PassFort - in-page strength meter (content script)
 *
 * Injected ONLY when the user clicks "Activate on this page" in the popup.
 *
 * Shows, under a password field:
 *   - live strength meter + tips
 *   - a warning if the page or the form's target uses insecure HTTP
 *   - a warning if the password contains the user's own name/username/email
 *
 * PRIVACY / SECURITY:
 *  - Everything stays in memory in this isolated script. No messaging,
 *    storage, network, or logging of the password or the other form values.
 *  - Other form fields are read only to compare, never password-type fields.
 *  - UI lives in a CLOSED shadow root; built with createElement + textContent.
 */
(function () {
    'use strict';

    if (window.__passfortActive) return;
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
    .warn {
      margin-bottom: 8px; padding: 6px 8px; font-size: 12px; font-weight: 600;
      color: #fecaca; background: rgba(239, 68, 68, 0.15);
      border: 1px solid #ef4444; border-radius: 6px;
    }
    .warn[hidden] { display: none; }
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

    const warnEl = el('div', 'warn');
    warnEl.setAttribute('role', 'alert');
    warnEl.hidden = true;

    const meter = el('div', 'meter');
    meter.setAttribute('aria-hidden', 'true');
    for (let i = 0; i < 4; i++) meter.appendChild(el('span', 'seg'));

    const detailEl = el('div', 'detail');
    const tipsEl = el('ul', 'tips');

    panel.append(head, warnEl, meter, detailEl, tipsEl);
    shadow.appendChild(panel);
    document.documentElement.appendChild(host);

    // ---------- Page-security + personal-info helpers ----------

    // Forms/documents can shadow their own methods via named inputs (DOM clobbering),
    // so we call the built-in methods directly instead of form.getAttribute(...) etc.
    const getAttr = (node, name) => Element.prototype.getAttribute.call(node, name);
    const queryAll = (root, selector) =>
        (root === document ? Document : Element).prototype.querySelectorAll.call(root, selector);

    // Returns a warning string, or '' if nothing is wrong.
    function securityWarning(field) {
        // 1) Page itself loaded over plain HTTP (localhost/127.0.0.1 count as secure)
        if (!window.isSecureContext) {
            return 'Not secure: this page uses HTTP, so a password typed here can be intercepted.';
        }
        // 2) Secure page, but the form posts to an http:// address
        const form = field.form;
        const action = form ? getAttr(form, 'action') : null;
        if (action) {
            try {
                if (new URL(action, location.href).protocol === 'http:') {
                    return 'Warning: this form sends your password over insecure HTTP.';
                }
            } catch (err) { /* invalid URL: ignore */ }
        }
        return '';
    }

    // Names / usernames / emails typed in the same form (never password fields).
    function collectPersonalInfo(field) {
        const root = field.form || document;
        const values = [];
        for (const input of queryAll(root, 'input')) {
            if (input === field) continue;
            const type = (input.type || 'text').toLowerCase();
            if (type !== 'text' && type !== 'email' && type !== 'tel') continue;
            const value = input.value.trim();
            if (value.length >= 3 && value.length <= 100) values.push(value);
            if (values.length >= 10) break;
        }
        return values;
    }

    // ---------- Behaviour ----------
    let activeField = null;

    function isPasswordInput(node) {
        return node instanceof HTMLInputElement && node.type === 'password';
    }

    function render(result, warning) {
        panel.dataset.level = String(result.score);
        if (labelEl.textContent !== result.label) labelEl.textContent = result.label;
        warnEl.textContent = warning;
        warnEl.hidden = !warning;
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
        if (top + panel.offsetHeight > window.innerHeight - margin &&
            rect.top - panel.offsetHeight - 6 > margin) {
            top = rect.top - panel.offsetHeight - 6;
        }
        panel.style.left = left + 'px';
        panel.style.top = top + 'px';
    }

    function update() {
        if (!activeField || !activeField.isConnected) { hide(); return; }
        // value + personal info are used here and not kept
        render(assess(activeField.value, collectPersonalInfo(activeField)),
            securityWarning(activeField));
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

    document.addEventListener('focusin', (e) => {
        if (isPasswordInput(e.target)) { activeField = e.target; update(); }
    }, true);

    document.addEventListener('input', (e) => {
        if (e.target === activeField) update();
    }, true);

    document.addEventListener('focusout', (e) => {
        if (e.target !== activeField) return;
        if (isPasswordInput(e.relatedTarget)) return;
        hide();
    }, true);

    window.addEventListener('scroll', schedulePlace, true);
    window.addEventListener('resize', schedulePlace);

    if (isPasswordInput(document.activeElement)) {
        activeField = document.activeElement;
        update();
    }
})();