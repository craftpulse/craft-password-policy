// Type declaration for window.passwordpolicy
declare global {
    interface Window {
        passwordpolicy: {
            showStrengthIndicator: boolean;
        };
        Craft?: {
            actionUrl?: string;
            csrfTokenName?: string;
            csrfTokenValue?: string;
        };
    }
}

// Import our CSS
import '~/css/app.css';

/**
 * CP password strength indicator (P1.12 layer 4b)
 *
 * Thin AJAX renderer against `password-policy/validation/validate`. The
 * server-side StrengthService picks engine A (baseline) or engine B
 * (zxcvbn-php Pro opt-in) — this client just paints the bars. Same code
 * path that drives the front-end consumer builders, so blocklist hits,
 * per-group policy resolution, and the `useZxcvbnStrength` toggle all
 * flow through here for free.
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
 */

// =========================================================================
// Selectors + constants
// =========================================================================

const INPUT_SELECTOR =
    'input[type="password"][autocomplete="new-password"]:not([data-pp-no-strength])';
const DEBOUNCE_MS = 250;
const BAR_ID_PREFIX = 'pp-cp-strength-bar-';

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
 * Engine B's `score` (0-4) maps directly: 0 → 1 bar, 4 → 5 bars.
 * Engine A only sends `label`, so we map onto a coarser fill count.
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
 * Renders the 5-bar HTML for the given (label, fillCount).
 */
function renderBar(label: string | null, fill: number, barId: string): string {
    const activeClass = label !== null ? (labelColor[label] ?? defaultBarClass) : defaultBarClass;

    const bars = Array.from({ length: 5 }, (_, index) => {
        const isActive = fill > 0 && index < fill;
        return `<span class="${isActive ? activeClass : defaultBarClass}"></span>`;
    }).join('');

    return `
        <div id="${barId}" class="pp-grid pp-grid-cols-5 pp-gap-x-1 pp-h-2 -pp-mt-4">
            ${bars}
        </div>`;
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
 */
function postValidate(password: string, cb: (response: ValidateResponse) => void): void {
    const formData = new FormData();
    formData.append('password', password);

    const url = window.Craft?.actionUrl
        ? `${window.Craft.actionUrl}/password-policy/validation/validate`
        : '/index.php?p=admin/actions/password-policy/validation/validate';

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
            cb(json);
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
    ruleCount?: number;
    lengthTier?: number;
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
 */
function bindIndicator(input: HTMLInputElement): void {
    const anchor = attachAnchor(input);
    if (!anchor) return;

    counter += 1;
    const barId = `${BAR_ID_PREFIX}${counter}`;

    // Initial empty bar
    anchor.insertAdjacentHTML('afterend', renderBar(null, 0, barId));

    let timer: number | null = null;

    input.addEventListener('input', function() {
        if (timer !== null) {
            window.clearTimeout(timer);
        }

        timer = window.setTimeout(() => {
            const password = input.value;
            const existing = document.getElementById(barId);

            // Empty input — clear the bar.
            if (password.length === 0) {
                if (existing) {
                    existing.remove();
                }
                anchor.insertAdjacentHTML('afterend', renderBar(null, 0, barId));
                return;
            }

            postValidate(password, (response) => {
                const strength = response.strength ?? {};
                const fill = fillCount(strength);
                const label = strength.label ?? null;

                const current = document.getElementById(barId);
                if (current) {
                    current.remove();
                }
                anchor.insertAdjacentHTML('afterend', renderBar(label, fill, barId));
            });
        }, DEBOUNCE_MS);
    });
}

// =========================================================================
// Boot
// =========================================================================

function init(): void {
    if (!window.passwordpolicy?.showStrengthIndicator) {
        return;
    }

    const inputs = document.querySelectorAll<HTMLInputElement>(INPUT_SELECTOR);
    inputs.forEach(bindIndicator);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
