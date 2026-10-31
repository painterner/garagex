# Security

Do not publish credentials, private keys, internal tokens, database files, source URLs
containing secrets, or production logs in GitHub issues or pull requests.

Runtime secrets are generated per installation under the ignored .runtime/ directory.
The platform's main S3 credential is administrator-only. Public S3 object responses use
a browser sandbox policy to isolate active HTML/SVG from the management console.

Management APIs and proxy/network APIs require S3 SigV4 header authentication.
Object downloads use an opaque, 60-second capability URL created by an authenticated
management request. The holder of that URL can download the selected object during
its validity; tenant/key status and bucket ownership are checked again.
Plain bearer account tokens are not accepted for external APIs. Streaming benchmark uploads verify the signature before
reading their body, then validate the full signed payload hash afterward.

Report security issues privately to the repository owner rather than opening a public
issue with an exploit or sensitive deployment data.
