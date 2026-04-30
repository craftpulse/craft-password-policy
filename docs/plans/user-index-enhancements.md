# User Index Enhancements

## Feature 1: Admin Password Change Action

Currently admins can only "Copy password reset URL" for other users. This is cumbersome when an admin needs to take immediate action (e.g. security incident, locked-out user).

**Add:** An element action on the Users index that lets admins set a new password directly. Could be:
- A modal with a password field (like Craft's own "Set Password" on the user edit page, but as a bulk/single action)
- Or a "Force New Password" action that generates a random strong password and emails it

**Edition:** Lite (core admin functionality)
**Priority:** High — common admin workflow gap

## Feature 2: Table Attributes on Users Index

We already have condition rules for filtering (Password Expired, Password Reset Required, Password Never Changed). These should also be available as **table columns** in the Users index so admins can see status at a glance without filtering.

**Add as table attributes:**
- Password Expired (yes/no badge or date)
- Password Reset Required (yes/no badge)
- Last Password Change (date)
- Password Status (current/expiring/expired/reset_required/never_changed)

**Note:** We're already extending the User element with condition rules. Table attributes use `EVENT_REGISTER_TABLE_ATTRIBUTES` and `EVENT_SET_TABLE_ATTRIBUTE_HTML` — same pattern.

**Edition:** Lite (visibility features should be free)
**Priority:** Medium — improves admin UX significantly
