# pwsafe-service

A web service for [Password Safe](https://pwsafe.org/) that provides browser-based, read-only access to your .psafe3 files, no client app required.

> ⚠️ **Security Notice**: This service has optional service-level authentication. If exposing this service to the internet, it is strongly recommended to enable authentication before doing so. Use of HTTPS is strongly recommended regardless if running in secured or unsecured mode.

## For Users

Want to deploy and use pwsafe-service? See the **[User Guide](docs/user.md)**.

## For Developers

Want to contribute or build from source? See the **[Developer Guide](docs/dev.md)**.

## FAQ

### Why read only?

I typically manage my password safes using the free Windows client, but sometimes I'm on a platform where a free client doesn't exist. This service gives me at least easy read access to my passwords from any platform. If someone wants to add write support, I'd happily review a contribution.

### Is there service-level authentication?

Yes. On first run, you choose between unsecured mode or secured mode. See the **[User Guide](docs/user.md)** for details.

### Why no multi-user support?

I'm the only Password Safe user in my household, so multi-user support isn't a priority for me. If someone wants to add it though, I'd happily review a contribution.

### Should I open a pull request or issue first?

- For features, it is recommended to first open an issue to discuss what you want and how you intend to implement a solution.
- For bug fixes, a pull request from the start is fine, but make sure to include reproduction instructions in the description.

## License

MIT License - see [LICENSE](LICENSE) file for details.
