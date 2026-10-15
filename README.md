# [Godot][] on [ATProto][]

This uses the [Godot Rust bindings][1] to link to the atrium crates for client
development to allow for games to interact with ATProto services like Appviews
and a PDS.

## Features

- Signs in using the OAuth authorization flow and stores the token into application configuration
- Invoke XRPC queries and procedures

[1]: https://godot-rust.github.io/
[godot]: https://godotengine.org/
[atproto]: https://atproto.com/
