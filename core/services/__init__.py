"""Service layer for the security-sensitive parts of the application.

Keeping TOTP, rate limiting and audit logic out of the views makes the pieces
reusable if the authentication flow is later extracted into its own service.
"""
