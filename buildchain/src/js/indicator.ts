// Type declaration for window.passwordpolicy
declare global {
    interface Window {
        // Optional: the flag now ships via a <meta> tag (CSP-safe); the
        // global is only a legacy fallback and may be absent.
        passwordpolicy?: {
            showStrengthIndicator: boolean;
        };
        Craft?: {
            actionUrl?: string;
            csrfTokenName?: string;
            csrfTokenValue?: string;
            t?: (category: string, message: string) => string;
        };
    }
}

// Import our CSS
import '~/css/app.css';

/**
 * CP password strength indicator (P1.12 layer 4b)
 *
 * Thin AJAX renderer against `password-policy/validation/validate`. The
 * server-side StrengthService runs zxcvbn-php and returns
 * `{engine, label, score, crackTime, suggestions, warning}` — this client
 * just paints the bars. Same code path that drives the front-end consumer
 * builders, so blocklist hits and per-group policy resolution flow through
 * here for free.
 *
 * Selector: every CP `<input type="password" autocomplete="new-password">`
 * not opted out via `data-pp-no-strength`. That covers the admin account
 * password screen, set-password, the installer, the new-user create form,
 * and any plugin field built with `forms.passwordField` + the standard
 * autocomplete hint. Confirmation fields and current-password fields use
 * different autocomplete values, so they're skipped.
 *
 * Failure mode: silent. If the AJAX request fails or returns non-2xx, the
 * bars freeze at their last known state. Strength UX is non-blocking; the
 * server-side validator on save remains the gate.
 *
 * @author CraftPulse
 * @since 5.2.0
 */

// =========================================================================
// Selectors + constants
// =========================================================================

const INPUT_SELECTOR =
    'input[type="password"][autocomplete="new-password"]:not([data-pp-no-strength])';
const DEBOUNCE_MS = 250;
const BAR_ID_PREFIX = 'pp-cp-strength-bar-';
const BOUND_ATTR = 'data-pp-strength-bound';

// =========================================================================
// Color stops keyed by label
// =========================================================================

const labelColor: Record<string, string> = {
    weak: 'pp-bg-red-400',
    fair: 'pp-bg-orange-400',
    strong: 'pp-bg-teal-400',
    excellent: 'pp-bg-green-500',
};

const defaultBarClass = 'pp-bg-slate-200 pp-h-2';

// =========================================================================
// Helpers
// =========================================================================

/**
 * Maps the server's strength block onto a 5-bar fill count.
 *
 * zxcvbn's `score` (0-4) maps directly: 0 → 1 bar, 4 → 5 bars. Falls back
 * to the label vocabulary if `score` is missing — defensive against any
 * future engine swap that returns labels only.
 */
function fillCount(strength: { label?: string; score?: number | null }): number {
    if (typeof strength.score === 'number') {
        return Math.max(1, Math.min(5, strength.score + 1));
    }

    switch (strength.label) {
        case 'weak':
            return 1;
        case 'fair':
            return 2;
        case 'strong':
            return 3;
        case 'excellent':
            return 5;
        default:
            return 0;
    }
}

/**
 * Escapes a string for safe interpolation into an HTML attribute value.
 * The strength label is a controlled server vocabulary and the name comes
 * from a translation file, but both land in attributes via string
 * interpolation below — escape defensively so a stray quote or angle
 * bracket can't break out.
 */
function escapeAttr(value: string): string {
    return value
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

/**
 * Renders the 5-bar HTML for the given (label, fillCount).
 *
 * The container carries `role="progressbar"` + `aria-valuemin/max/now`
 * and (when a label is known) `aria-valuetext`, so screen-reader users
 * get the strength signal the colored bars convey visually. Without it
 * the meter is a row of decorative `<span>`s announcing nothing — the
 * front-end consumer builder already exposes `aria-valuenow`, so the CP
 * meter matched that contract here.
 */
function renderBar(label: string | null, fill: number, barId: string): string {
    const activeClass = label !== null ? (labelColor[label] ?? defaultBarClass) : defaultBarClass;

    const bars = Array.from({ length: 5 }, (_, index) => {
        const isActive = fill > 0 && index < fill;
        return `<span class="${isActive ? activeClass : defaultBarClass}"></span>`;
    }).join('');

    const name = escapeAttr(window.Craft?.t?.('password-policy', 'Password strength') ?? 'Password strength');
    const valueText = label !== null ? ` aria-valuetext="${escapeAttr(label)}"` : '';

    return `
        <div id="${barId}" class="pp-grid pp-grid-cols-5 pp-gap-x-1 pp-h-2 -pp-mt-4" role="progressbar" aria-label="${name}" aria-valuemin="0" aria-valuemax="5" aria-valuenow="${fill}"${valueText}>
            ${bars}
        </div>`;
}

/**
 * Updates an EXISTING progressbar node in place — fill classes, the live
 * `aria-valuenow`, and `aria-valuetext` — rather than tearing it down and
 * re-inserting fresh markup on every keystroke.
 *
 * Re-creating the node breaks screen-reader value-change announcements: SR
 * software tracks the live region by node identity, so a removed+re-inserted
 * progressbar reads as a brand-new element each time instead of a value
 * update, and `aria-valuetext` never announces as a change. Mutating the
 * same node preserves that contract.
 */
function updateBar(node: HTMLElement, label: string | null, fill: number): void {
    const activeClass = label !== null ? (labelColor[label] ?? defaultBarClass) : defaultBarClass;

    const spans = node.querySelectorAll<HTMLSpanElement>(':scope > span');
    spans.forEach((span, index) => {
        const isActive = fill > 0 && index < fill;
        span.className = isActive ? activeClass : defaultBarClass;
    });

    node.setAttribute('aria-valuenow', String(fill));
    if (label !== null) {
        node.setAttribute('aria-valuetext', label);
    } else {
        node.removeAttribute('aria-valuetext');
    }
}

/**
 * Returns the wrapper element we should attach the bar after — the input's
 * closest `.field` ancestor (Craft's standard `forms.passwordField` markup).
 * Falls back to the immediate parent if no ancestor matches.
 */
function attachAnchor(input: HTMLInputElement): HTMLElement {
    return (input.closest('.field') as HTMLElement | null) ?? (input.parentElement as HTMLElement);
}

/**
 * POSTs the password to the validate endpoint. Failure is silent — `cb`
 * is only called on a successful 2xx with parseable JSON.
 *
 * `token` is echoed back to the callback so the caller can drop a stale
 * response: a slow earlier request must not clobber the bar state painted
 * by a newer one (request sequencing).
 */
function postValidate(password: string, token: number, cb: (response: ValidateResponse, token: number) => void): void {
    const formData = new FormData();
    formData.append('password', password);

    // Fallback path uses Craft 5's native `/actions/...` route, which works
    // regardless of the installed `cpTrigger` (the previous `admin/actions/...`
    // fallback broke on installs that customized cpTrigger).
    const url = window.Craft?.actionUrl
        ? `${window.Craft.actionUrl}/password-policy/validation/validate`
        : '/actions/password-policy/validation/validate';

    const xhr = new XMLHttpRequest();
    xhr.open('POST', url, true);
    xhr.setRequestHeader('Accept', 'application/json');
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

    const csrf = window.Craft?.csrfTokenValue ?? null;
    if (csrf) {
        const csrfName = window.Craft?.csrfTokenName ?? 'CRAFT_CSRF_TOKEN';
        formData.append(csrfName, csrf);
    }

    xhr.onreadystatechange = function() {
        if (xhr.readyState !== 4) return;
        if (xhr.status < 200 || xhr.status >= 300) return;

        try {
            const json = JSON.parse(xhr.responseText) as ValidateResponse;
            cb(json, token);
        } catch {
            // Bad JSON — silent failure, keep last bar state.
        }
    };

    xhr.send(formData);
}

// =========================================================================
// Types
// =========================================================================

interface StrengthBlock {
    engine?: string;
    label?: string;
    score?: number | null;
    suggestions?: string[];
    crackTime?: string;
    warning?: string;
}

interface ValidateResponse {
    strength?: StrengthBlock;
}

// =========================================================================
// Per-input binding
// =========================================================================

let counter = 0;

/**
 * Binds the strength indicator to a single password input.
 *
 * Idempotent — guarded by a `data-pp-strength-bound` attribute so the
 * MutationObserver (which may surface the same input multiple times
 * when subtree mutations cascade) doesn't stack listeners or duplicate
 * the bar DOM. Inputs that already carry the attribute are skipped.
 */
function bindIndicator(input: HTMLInputElement): void {
    if (input.hasAttribute(BOUND_ATTR)) return;
    input.setAttribute(BOUND_ATTR, '1');

    const anchor = attachAnchor(input);
    if (!anchor) return;

    counter += 1;
    const barId = `${BAR_ID_PREFIX}${counter}`;

    // Initial empty bar — the ONLY insert. Every subsequent update mutates
    // this node in place (see updateBar) so SR value announcements survive.
    anchor.insertAdjacentHTML('afterend', renderBar(null, 0, barId));

    let timer: number | null = null;
    // Monotonic request token — the callback drops responses that a newer
    // keystroke has already superseded.
    let requestToken = 0;

    input.addEventListener('input', function() {
        if (timer !== null) {
            window.clearTimeout(timer);
        }

        timer = window.setTimeout(() => {
            const password = input.value;
            const existing = document.getElementById(barId);

            // Empty input — reset the bar to its neutral state in place.
            if (password.length === 0) {
                requestToken += 1;
                if (existing) {
                    updateBar(existing, null, 0);
                }
                return;
            }

            requestToken += 1;
            const thisToken = requestToken;

            postValidate(password, thisToken, (response, token) => {
                // Stale response — a newer request superseded this one.
                if (token !== requestToken) {
                    return;
                }

                const strength = response.strength ?? {};
                const fill = fillCount(strength);
                const label = strength.label ?? null;

                const current = document.getElementById(barId);
                if (current) {
                    updateBar(current, label, fill);
                }
            });
        }, DEBOUNCE_MS);
    });
}

// =========================================================================
// Scan + observe
// =========================================================================

/**
 * Binds the indicator to every matching password input under `root`.
 * Used by the initial `init()` scan of `document` and recursively on
 * mutation-added subtrees.
 */
function scan(root: ParentNode): void {
    const inputs = root.querySelectorAll<HTMLInputElement>(INPUT_SELECTOR);
    inputs.forEach(bindIndicator);
}

/**
 * Watches the document for password inputs added after the initial
 * scan — modals (e.g. the plugin's own admin Change-Password modal in
 * `ChangeUserPassword::registerModalHelper`), slideouts, HUDs, and any
 * other dynamically-rendered surface. Without this, the strength meter
 * silently no-ops on every input that joined the DOM after
 * `DOMContentLoaded`.
 *
 * Each mutation's `addedNodes` is checked two ways:
 *  1. The added node itself matches the selector — bind directly.
 *  2. The added node contains matching descendants — bind each.
 *
 * Idempotency is enforced by `bindIndicator`'s `data-pp-strength-bound`
 * guard, so re-observing a subtree (common when modal helpers rewrap
 * markup) is safe.
 *
 * Cost: the callback only runs `querySelectorAll(INPUT_SELECTOR)` per
 * added Element node, and the selector is narrow
 * (`input[type=password][autocomplete=new-password]`), so each scan is a
 * cheap native subtree query. The high-frequency CP mutators are bounded:
 * drag-sort scans the small moved subtree per pointer move (sub-ms);
 * Live Preview content mutates inside an iframe (a separate document this
 * `document.body` observer never sees); HUD/queue polling swaps a handful
 * of nodes. The observer only starts when `showStrengthIndicator` is on
 * (see `init()`), and a page-lifetime observer is GC'd on navigation.
 */
function startObserver(): void {
    const observer = new MutationObserver((mutations) => {
        for (const m of mutations) {
            for (const node of Array.from(m.addedNodes)) {
                if (!(node instanceof Element)) continue;

                if (node.matches(INPUT_SELECTOR)) {
                    bindIndicator(node as HTMLInputElement);
                }

                scan(node);
            }
        }
    });

    observer.observe(document.body, { childList: true, subtree: true });
}

// =========================================================================
// Boot
// =========================================================================

/**
 * Reads the `showStrengthIndicator` flag.
 *
 * Primary source is the `<meta name="pp-show-strength-indicator">` tag
 * emitted by `PasswordPolicyAsset` — a meta tag carries the flag without an
 * inline <script>, so it survives a strict-nonce CSP that would otherwise
 * block a bare bootstrap. Falls back to `window.passwordpolicy` for any
 * legacy consumer that still sets the global directly.
 */
function shouldShow(): boolean {
    const meta = document.querySelector<HTMLMetaElement>('meta[name="pp-show-strength-indicator"]');
    if (meta) {
        return meta.content === '1';
    }

    return Boolean(window.passwordpolicy?.showStrengthIndicator);
}

function init(): void {
    if (!shouldShow()) {
        return;
    }

    scan(document);
    startObserver();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
