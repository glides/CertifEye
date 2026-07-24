# Safety and upload rules

The tool is a defensive read-only assessment aid. It does not issue certificates,
exploit ESC conditions, coerce authentication, relay credentials, or provide
attack execution steps.

Never request or upload raw exports, salts, token maps, raw event messages, local
manifests containing sensitive context, or files marked `DO_NOT_UPLOAD`. Review
representative scrubbed output and the safe manifest before sharing. Equal tokens
are correlation handles, not identities to be guessed or reversed.
