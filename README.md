# pwsafe-service

A web service for [Password Safe](https://pwsafe.org/) that provides browser-based, read-only access to your .psafe3 files, no client app required.

> ⚠️ **Security Notice**: This service has no built-in authentication beyond the master password required to open each safe. It is intended for **local or private network use only**. Do not expose it to the public internet. Use of HTTPS is strongly recommended.

## For Users

Want to deploy and use pwsafe-service? See the **[User Guide](docs/user.md)**.

## For Developers

Want to contribute or build from source? See the **[Developer Guide](docs/dev.md)**.

## FAQ

### Why read only?

Currently my requirements for this service are that it provides read-only access to my password safes. Allowing write access would mean:

- Creating additional frontend UI
- Determining a policy for resolving change conflicts for remotely synced password safes

Until my requirements change to include write access, the above list are not things I am interested in spending time on. However, if someone wants this service to support write access, I would happily review changes to enable it.

### Should I open a pull request or issue first?

- For features, it is recommended to first open an issue to discuss what you want and how you intend to implement a solution.
- For bug fixes, a pull request from the start is fine, but make sure to include reproduction instructions in the description.

## License

MIT License - see [LICENSE](LICENSE) file for details.
