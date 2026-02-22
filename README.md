# pwsafe-service

A web service for [Password Safe](https://pwsafe.org/) that provides browser-based, read-only access to your .psafe3 files, no client app required.

> ⚠️ **Security Notice**: This service has optional authentication. If exposing this service to the internet, it is strongly recommended to enable authentication before doing so. Use of HTTPS is strongly recommended.

## For Users

Want to deploy and use pwsafe-service? See the **[User Guide](docs/user.md)** and **[Configuration Reference](docs/configuration.md)**.

## For Developers

Want to contribute or build from source? See the **[Developer Guide](docs/dev.md)**.

## FAQ

### What do you use this for?

I typically manage my password safe using the free Windows client, but sometimes I'm on a machine where:

- A free client doesn't exist for the machine's OS
- I don't want to put my .psafe3 files on the machine

Therefore I use this service for easy read access to my password safe from any machine.

### Why read only?

If I really need to add or modify entries in my password safe, I'm content with waiting until I can get on my Windows machine. If someone wants to add write support though, I'd happily review a contribution.

### Is there service authentication?

On first run, you choose if you want service authentication. See the **[User Guide](docs/user.md#set-up-authentication)** for details.

### Why no multi-user support?

I'm the only Password Safe user in my household, so multi-user support isn't a priority for me. If someone wants to add multi-user support though, I'd happily review a contribution.

### Should I open a pull request or issue first?

- For features, it is recommended to first open an issue to discuss what you want and how you intend to implement a solution.
- For bug fixes, a pull request from the start is fine, but make sure to include reproduction instructions in the description.

## License

MIT License - see [LICENSE](LICENSE) file for details.
