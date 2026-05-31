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
     * Resolves the wrapper for a given password input — the `<div data-pp-field="X">`.
     */
    function fieldWrapper(input) {
        var id = input.id;
        if (!id) return null;
        return document.querySelector('[data-pp-field="' + id + '"]');
    }

    /**
     * Returns the live region span associated with an input.
     */
    function liveRegion(input) {
        return document.querySelector('[data-pp-live-region="' + input.id + '"]');
    }

    /**
     * POSTs the current password to the validate endpoint.
     */
    function validate(input, payload, callback) {
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
                    callback(null, json);
                } catch (e) {
                    callback(e, null);
                }
            } else {
                callback(new Error('HTTP ' + xhr.status), null);
            }
        };

        xhr.send(formData);
    }

    /**
     * Updates the requirement list / strength meter / submit gate / live
     * region from a validate response.
     */
    function applyResponse(input, response) {
        var wrapper = fieldWrapper(input);
        if (!wrapper) return;

        var passed = response.passed === true || (response.errors && response.errors.length === 0);
        input.setAttribute('aria-invalid', passed ? 'false' : 'true');
        input.setAttribute('aria-busy', 'false');

        // Map response.errors to per-rule pass/fail. Server returns a list
        // of error messages per attribute key — we encode "rule X failed"
        // as a non-empty entry under errorsByKey when present.
        var errorsByKey = response.errorsByKey || {};
        var requirements = document.querySelectorAll('[data-pp-requirement]');
        requirements.forEach(function(li) {
            var key = li.getAttribute('data-pp-requirement');
            li.classList.remove('pp-pass', 'pp-fail', 'pp-pending');
            if (errorsByKey[key]) {
                li.classList.add('pp-fail');
            } else {
                li.classList.add('pp-pass');
            }
        });

        // Strength meter
        var strength = response.strength || {};
        var meters = document.querySelectorAll('[data-pp-strength]');
        meters.forEach(function(meter) {
            meter.classList.remove(
                'pp-strength-weak',
                'pp-strength-fair',
                'pp-strength-strong',
                'pp-strength-excellent',
            );
            if (strength.label) {
                meter.classList.add('pp-strength-' + strength.label);
                meter.setAttribute('aria-valuenow', String(strength.score != null ? strength.score : 0));
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
            if (passed) {
                live.textContent = 'Password meets all requirements.';
            } else {
                var firstError = (response.errors && response.errors[0]) || 'Password does not meet requirements.';
                live.textContent = firstError;
            }
        }
    }

    /**
     * Binds an input to the live-validation pipeline.
     */
    function bindValidate(input) {
        var timer = null;

        input.addEventListener('input', function() {
            if (timer) clearTimeout(timer);

            input.setAttribute('aria-busy', 'true');

            timer = setTimeout(function() {
                var pwd = input.value;

                if (!pwd) {
                    // Empty input — clear state
                    input.setAttribute('aria-busy', 'false');
                    input.removeAttribute('aria-invalid');
                    var requirements = document.querySelectorAll('[data-pp-requirement]');
                    requirements.forEach(function(li) {
                        li.classList.remove('pp-pass', 'pp-fail', 'pp-pending');
                    });
                    var live = liveRegion(input);
                    if (live) live.textContent = '';
                    return;
                }

                var groupAttr = input.getAttribute('data-pp-context-groups') || '';
                var groups = groupAttr ? groupAttr.split(',').map(function(s) { return s.trim(); }).filter(Boolean) : [];

                validate(input, { password: pwd, groups: groups }, function(err, response) {
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
