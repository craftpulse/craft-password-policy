<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\events;

use yii\base\Event;

/**
 * Class WebhookDeliveryAttemptEvent
 *
 * Fired after every dispatch attempt by `WebhookService::dispatch()` —
 * success or failure. Lets observability listeners (compliance
 * dashboards, third-party APMs, custom log targets) capture per-
 * delivery outcomes without subscribing to the audit-log writes
 * themselves.
 *
 * Edition: every — capture surface. The webhook delivery itself is
 * Enterprise-only (the queue job is gated, the CP UI is gated), but the
 * event class fires regardless of edition because a non-Enterprise
 * install can still synthesise a dispatch in tests or via custom code.
 * Edition gates apply to the read surfaces that consume the event, not
 * to the event itself. See `project_audit_capture_principle.md`.
 *
 * Privacy invariant: NEVER include the HMAC signature, plaintext
 * secret, or full request body in the event payload. The body is
 * already in the audit log row that drove the dispatch; consumers can
 * correlate via `auditRowId`. The signature and secret material are
 * cryptographic identifiers that downstream listeners have no
 * legitimate reason to receive.
 *
 * @event WebhookDeliveryAttemptEvent
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class WebhookDeliveryAttemptEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var int the audit-log row id this dispatch attempted to deliver.
     *     Stable correlation key — listeners can join against
     *     `passwordpolicy_audit_log` on this id to recover the full
     *     payload.
     */
    public int $auditRowId;

    /**
     * @var int duration of the dispatch in milliseconds, measured around
     *     the Guzzle call. Includes connect, TLS handshake, send,
     *     receive. A timeout produces a value at or above the configured
     *     timeout ceiling (10s by default).
     */
    public int $duration;

    /**
     * @var int the endpoint id the dispatch targeted.
     */
    public int $endpointId;

    /**
     * @var string|null human-readable error message on dispatch failure
     *     — Guzzle exception message, transport error, etc. Null on
     *     success. Never includes the request body or signature
     *     material.
     */
    public ?string $errorMessage = null;

    /**
     * @var int|null HTTP status code returned by the endpoint, or null
     *     when the dispatch failed before a response (connect refusal,
     *     DNS failure, timeout). Distinguishing "endpoint refused" from
     *     "endpoint returned 4xx/5xx" matters for circuit-breaker
     *     triage.
     */
    public ?int $statusCode = null;

    /**
     * @var bool whether the dispatch was treated as a success by the
     *     service. Success = 2xx HTTP response. 4xx, 5xx, transport
     *     failure, and timeouts all map to false.
     */
    public bool $success = false;
}
