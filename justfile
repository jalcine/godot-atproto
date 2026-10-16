godot := env('GODOT', env('HOME') / '.local/share/mise/installs/aqua-godotengine-godot/4.6.3-stable/godot')
example := 'examples/simple'
manifest := 'extension/Cargo.toml'

default:
    @just --list

# Build the Rust extension (debug)
build:
    cargo build --manifest-path {{manifest}}

# Run the Rust extension tests
test:
    cargo test --manifest-path {{manifest}}

# Run the example game
run: build
    {{godot}} --path {{example}}

# Run the jetstream guessing-game example
run-jetstream: build
    {{godot}} --path examples/jetstream

# Run the rpg.actor example, combining AtprotoClient with the public rpg.actor API
run-rpg-actor: build
    {{godot}} --path examples/rpg.actor

# Open the example game in the Godot editor
edit: build
    {{godot}} --editor --path {{example}}
