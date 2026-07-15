# Security Policy

GuardAgent is security-sensitive software. Please report suspected vulnerabilities privately and avoid including exploit details, credentials, personal data, or production logs in issues or pull requests.

## Supported versions

Before the first stable release, security fixes are made on the latest `main` branch. After tagged releases begin, this section will identify the supported release lines.

## Reporting a vulnerability

If you have access to this repository, create a private draft advisory from the repository's **Security and quality > Advisories** page:

https://github.com/yuanmouensis313/GuardAgent/security/advisories/new

If you cannot create an advisory, contact the repository owner through GitHub without posting technical details publicly. A dedicated security contact may be added before the repository becomes public.

Include, when available:

- the affected commit or version;
- the relevant GuardAgent mode and deployment environment;
- minimal reproduction steps using synthetic data;
- expected and observed behavior;
- potential impact and suggested mitigations.

Never submit real bearer tokens, private keys, OpenClaw configuration secrets, audit databases, or unredacted production events. Rotate any credential that may have been exposed before sending a report.

## Security boundary

GuardAgent adds execution-point policy enforcement and audit controls. It does not replace operating-system isolation, OpenClaw sandboxing, sender allowlists, native tool policy, or secure host administration. See [the deployment guide](docs/DEPLOYMENT.md) for the full boundary and rollout gates.
