A new custom domain name is converted to lowercase ASCII (punycode), with a
trailing dot removed, before availability and DNS validation checks. Invalid
names and wildcard registrations are rejected before storage.

A custom domain registration must complete validation within 48 hours of
creation. Retrying validation does not extend this window. Once validation
succeeds, the registration is exempt from this expiration policy.

Management removes expired, unvalidated registrations at startup and every
60 minutes. While management is running, removal normally occurs between
48 and 49 hours after registration. Validation is refused after the 48-hour
deadline even if cleanup has not yet removed the registration.

Removal releases the name for a new registration. The new registration must
complete its own validation. Its account does not inherit validation or
services from the expired registration.

The original account receives a system activity event named
`CustomDomainValidationExpired`, displayed as "Unvalidated domain registration
expired". The event includes the domain name, original registration ID, and
validation deadline.

On upgrade, existing unvalidated registrations receive a 48-hour validation
window. Restarting management does not extend a previously assigned deadline.

Registrations with existing services, including services using subdomains, are
retained for operator review. Management logs their account and domain IDs so
an operator can identify and resolve those dependencies before cleanup.

Manual deletion is also refused while any service uses the domain or a subdomain,
including disabled services. Delete those services or move them to another domain
before removing the registration. A refused deletion returns HTTP 412 and leaves
the domain and its services unchanged; no deletion activity event is recorded.
