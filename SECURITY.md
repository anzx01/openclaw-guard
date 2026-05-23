# Security Policy

## Supported Versions

Security fixes are provided for the latest published version of this project.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately before opening a public issue.
Use GitHub private vulnerability reporting if it is enabled on the repository,
or contact the repository owner by a private channel.

Include:

- A clear description of the issue.
- Steps to reproduce or a minimal proof of concept.
- Affected versions and environment details.
- Whether any secrets, user data, or audit logs may have been exposed.

## Sensitive Data

Do not commit real webhook URLs, Redis passwords, API keys, audit logs, or
production `security-config.yaml` files. Use `security-config.example.yaml` as
the public template and keep local configuration ignored by Git.
