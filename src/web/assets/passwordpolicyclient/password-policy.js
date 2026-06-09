/**
 * Password Policy front-end client (P1.12)
 *
 * Vanilla, framework-free, no Vite/build step required by consumer sites.
 * Attaches to inputs marked `data-pp-validate="1"`, AJAX-validates against
 * `password-policy/validate`, and toggles state classes on consumer-marked
 * slots. Show/hide toggle binding included.
 *
 * Does NOT minify itself — production projects can pipe through their own
 * asset pipeline if desired; the file size is small enough (~5KB) that
 * minification is not required.
 *
 * @author      CraftPulse
 * @since       5.2.0
 */

(function() {
    'use strict';

    var DEBOUNCE_MS = 250;

    /**
     * Returns the closest ancestor matching a CSS selector, or null.
     */
    function closest(el, selector) {
        while (el) {
            if (el.nodeType === 1 && el.matches(selector)) {
                return el;
            }
            el = el.parentNode;
        }
        return null;
    }

    /**
     * Returns the live region span associated with an input.
     */
    function liveRegion(input) {
        return document.querySelector('[data-pp-live-region="' + input.id + '"]');
    }

    /**
     * Resolves the requirement-list `<li>` elements and strength meters that
     * belong to a given input, SCOPED so typing in one field never repaints
     * another field's widget on the same page.
     *
     * Resolution order:
     *   1. Explicit association — any `[data-pp-for="{id}"]` slots (emitted by
     *      `StrengthMeterTag`/`RequirementListTag` when the consumer wires the
     *      field id). These win regardless of DOM position.
     *   2. Implicit scope — the nearest ancestor of the input that also
     *      contains a requirement list or strength meter (the composed-widget
     *      case, where `.pp-widget` wraps the field + its slots).
     *
     * Returns `{ requirements: Element[], meters: Element[] }`.
     */
    function resolveScope(input) {
        var id = input.id;
        var requirements = [];
        var meters = [];

        // 1. Explicit association via data-pp-for.
        if (id) {
            var taggedReqs = document.querySelectorAll('[data-pp-requirement][data-pp-for="' + id + '"]');
            var taggedMeters = document.querySelectorAll('[data-pp-strength][data-pp-for="' + id + '"]');
            if (taggedReqs.length || taggedMeters.length) {
                return {
                    requirements: Array.prototype.slice.call(taggedReqs),
                    meters: Array.prototype.slice.call(taggedMeters),
                };
            }
        }

        // 2. Implicit scope — walk up to the nearest ancestor that holds a
        //    requirement list or meter, and query only within it.
        var scope = input.parentNode;
        while (scope && scope.nodeType === 1) {
            if (scope.querySelector('[data-pp-requirement]') || scope.querySelector('[data-pp-strength]')) {
                break;
            }
            scope = scope.parentNode;
        }

        var root = (scope && scope.nodeType === 1) ? scope : document;
        requirements = Array.prototype.slice.call(root.querySelectorAll('[data-pp-requirement]'));
        meters = Array.prototype.slice.call(root.querySelectorAll('[data-pp-strength]'));

        return { requirements: requirements, meters: meters };
    }

    /**
     * Builds the set of client requirement keys whose server-side check is
     * still pending (`pass === null` — HIBP "checking"/"unable"). The server
     * returns each rule under `response.rules` keyed by its server key, so we
     * remap to the client `data-pp-requirement` vocabulary here, mirroring the
     * controller's `_clientKey()`.
     */
    function pendingKeySet(response) {
        var set = {};

        // Prefer an explicit server-emitted list if present.
        if (response.pendingKeys && response.pendingKeys.length) {
            response.pendingKeys.forEach(function(k) {
                set[k] = true;
            });
            return set;
        }

        var rules = response.rules || [];
        rules.forEach(function(rule) {
            if (rule && rule.pass === null) {
                set[clientKey(rule.key)] = true;
            }
        });

        return set;
    }

    /**
     * Mirrors `ValidationController::_clientKey()` — maps server rule keys to
     * the client `data-pp-requirement` vocabulary.
     */
    function clientKey(key) {
        switch (key) {
            case 'minLength':
            case 'maxLength':
                return 'length';
            case 'characterTypes':
                return 'character-types';
            case 'common':
                return 'blocklist';
            default:
                return key;
        }
    }

    /**
     * Sets the visually-hidden status span on a requirement `<li>` so the
     * met/not-met/pending state is exposed programmatically — the `::before`
     * glyph is decorative only and conveys nothing to assistive tech.
     */
    function setRequirementStatus(li, status) {
        var span = li.querySelector('[data-pp-requirement-status]');
        if (!span) {
            span = document.createElement('span');
            span.setAttribute('data-pp-requirement-status', '');
            span.className = 'pp-visually-hidden';
            li.appendChild(span);
        }

        var t = (window.Craft && window.Craft.t) ? window.Craft.t : function(_c, m) { return m; };
        var text = '';
        if (status === 'pass') {
            text = t('password-policy', 'met');
        } else if (status === 'fail') {
            text = t('password-policy', 'not met');
        } else if (status === 'pending') {
            text = t('password-policy', 'checking');
        }
        span.textContent = text ? '(' + text + ')' : '';
    }

    /**
     * POSTs the current password to the validate endpoint.
     */
    function validate(input, payload, token, callback) {
        var formData = new FormData();
        formData.append('password', payload.password);

        if (payload.groups && payload.groups.length) {
            payload.groups.forEach(function(g) {
                formData.append('groups[]', g);
            });
        }

        // Use the standard Craft action URL — same endpoint that the CP
        // password meter would use on Pro. Fallback path uses Craft 5's
        // native `/actions/...` route, which works regardless of the
        // installed `cpTrigger` (the previous `admin/actions/...` fallback
        // broke on installs that customized cpTrigger).
        var url = (window.Craft && window.Craft.actionUrl)
            ? window.Craft.actionUrl + '/password-policy/validation/validate'
            : '/actions/password-policy/validation/validate';

        var xhr = new XMLHttpRequest();
        xhr.open('POST', url, true);
        xhr.setRequestHeader('Accept', 'application/json');
        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

        // CSRF token — Craft exposes it via the head <meta> tag or
        // window.Craft.csrfTokenValue.
        var csrf = (window.Craft && window.Craft.csrfTokenValue) || null;
        if (csrf) {
            var csrfName = (window.Craft && window.Craft.csrfTokenName) || 'CRAFT_CSRF_TOKEN';
            formData.append(csrfName, csrf);
        }

        xhr.onreadystatechange = function() {
            if (xhr.readyState !== 4) return;
            if (xhr.status >= 200 && xhr.status < 300) {
                try {
                    var json = JSON.parse(xhr.responseText);
                    callback(null, json, token);
                } catch (e) {
                    callback(e, null, token);
                }
            } else {
                callback(new Error('HTTP ' + xhr.status), null, token);
            }
        };

        xhr.send(formData);
    }

    /**
     * Updates the requirement list / strength meter / submit gate / live
     * region from a validate response. All DOM queries are scoped to the
     * input's own field (see {@see resolveScope}) so widgets don't bleed
     * state across each other.
     */
    function applyResponse(input, response) {
        var scope = resolveScope(input);

        var errorsByKey = response.errorsByKey || {};
        var pending = pendingKeySet(response);

        // A field "passes" only when there are zero failures AND nothing is
        // still pending — a pending HIBP check must NOT open the submit gate.
        var hasPending = Object.keys(pending).length > 0;
        var noErrors = response.errors ? response.errors.length === 0 : Object.keys(errorsByKey).length === 0;
        var passed = (response.passed === true || noErrors) && !hasPending;

        input.setAttribute('aria-invalid', (response.passed === true || noErrors) ? 'false' : 'true');
        input.setAttribute('aria-busy', hasPending ? 'true' : 'false');

        // Map response.errors / pending to per-rule pass/fail/pending state.
        scope.requirements.forEach(function(li) {
            var key = li.getAttribute('data-pp-requirement');
            li.classList.remove('pp-pass', 'pp-fail', 'pp-pending');
            if (errorsByKey[key]) {
                li.classList.add('pp-fail');
                setRequirementStatus(li, 'fail');
            } else if (pending[key]) {
                li.classList.add('pp-pending');
                setRequirementStatus(li, 'pending');
            } else {
                li.classList.add('pp-pass');
                setRequirementStatus(li, 'pass');
            }
        });

        // Strength meter
        var strength = response.strength || {};
        scope.meters.forEach(function(meter) {
            meter.classList.remove(
                'pp-strength-weak',
                'pp-strength-fair',
                'pp-strength-strong',
                'pp-strength-excellent',
            );
            if (strength.label) {
                meter.classList.add('pp-strength-' + strength.label);
                meter.setAttribute('aria-valuenow', String(strength.score != null ? strength.score : 0));
                meter.setAttribute('aria-valuetext', strength.label);
                var labelEl = meter.querySelector('[data-pp-strength-label]');
                if (labelEl) {
                    labelEl.textContent = strength.label;
                }
            }
        });

        // Submit gate — find the gate selector on the input
        var gateSelector = input.getAttribute('data-pp-submit-gate');
        if (gateSelector) {
            var gate = document.querySelector(gateSelector);
            if (gate) {
                if (passed) {
                    gate.removeAttribute('disabled');
                } else {
                    gate.setAttribute('disabled', 'disabled');
                }
            }
        }

        // Live region announce
        var live = liveRegion(input);
        if (live) {
            var t = (window.Craft && window.Craft.t) ? window.Craft.t : function(_c, m) { return m; };
            if (hasPending) {
                live.textContent = t('password-policy', 'Checking password…');
            } else if (passed) {
                live.textContent = t('password-policy', 'Password meets all requirements.');
            } else {
                var firstError = (response.errors && response.errors[0]) || t('password-policy', 'Password does not meet requirements.');
                live.textContent = firstError;
            }
        }
    }

    /**
     * Clears all per-field state slots back to their neutral default.
     */
    function clearScope(input) {
        var scope = resolveScope(input);

        scope.requirements.forEach(function(li) {
            li.classList.remove('pp-pass', 'pp-fail', 'pp-pending');
            setRequirementStatus(li, '');
        });

        scope.meters.forEach(function(meter) {
            meter.classList.remove(
                'pp-strength-weak',
                'pp-strength-fair',
                'pp-strength-strong',
                'pp-strength-excellent',
            );
            meter.setAttribute('aria-valuenow', '0');
            meter.removeAttribute('aria-valuetext');
            var labelEl = meter.querySelector('[data-pp-strength-label]');
            if (labelEl) {
                labelEl.textContent = '';
            }
        });
    }

    /**
     * Binds an input to the live-validation pipeline.
     */
    function bindValidate(input) {
        var timer = null;
        // Monotonic request token — the callback compares against the latest
        // issued token so a slow earlier response can't clobber a newer one.
        var requestToken = 0;

        input.addEventListener('input', function() {
            if (timer) clearTimeout(timer);

            input.setAttribute('aria-busy', 'true');

            timer = setTimeout(function() {
                var pwd = input.value;

                if (!pwd) {
                    // Empty input — clear state. Bump the token so any
                    // in-flight response is discarded.
                    requestToken += 1;
                    input.setAttribute('aria-busy', 'false');
                    input.removeAttribute('aria-invalid');
                    clearScope(input);
                    var live = liveRegion(input);
                    if (live) live.textContent = '';
                    return;
                }

                var groupAttr = input.getAttribute('data-pp-context-groups') || '';
                var groups = groupAttr ? groupAttr.split(',').map(function(s) { return s.trim(); }).filter(Boolean) : [];

                requestToken += 1;
                var thisToken = requestToken;

                validate(input, { password: pwd, groups: groups }, thisToken, function(err, response, token) {
                    // Stale response — a newer request superseded this one.
                    if (token !== requestToken) {
                        return;
                    }
                    if (err) {
                        // API failure — clear busy, leave state alone.
                        input.setAttribute('aria-busy', 'false');
                        return;
                    }
                    applyResponse(input, response);
                });
            }, DEBOUNCE_MS);
        });
    }

    /**
     * Binds the show/hide visibility toggle.
     */
    function bindToggle(button) {
        var targetId = button.getAttribute('data-pp-toggle-visibility');
        if (!targetId) return;

        var target = document.getElementById(targetId);
        if (!target) return;

        button.addEventListener('click', function(e) {
            e.preventDefault();
            var isPassword = target.type === 'password';
            target.type = isPassword ? 'text' : 'password';
            button.setAttribute(
                'aria-label',
                isPassword ? 'Hide password' : 'Show password',
            );
            button.classList.toggle('pp-toggle-on', isPassword);

            // Flip the two glyph <svg> elements (open eye vs eye-slash).
            var open = button.querySelector('.pp-eye-open');
            var slash = button.querySelector('.pp-eye-slash');
            if (open && slash) {
                if (isPassword) {
                    open.style.display = 'none';
                    slash.style.display = '';
                } else {
                    open.style.display = '';
                    slash.style.display = 'none';
                }
            }
        });
    }

    function init() {
        var validateInputs = document.querySelectorAll('input[data-pp-validate="1"]');
        validateInputs.forEach(bindValidate);

        var toggles = document.querySelectorAll('[data-pp-toggle-visibility]');
        toggles.forEach(bindToggle);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
