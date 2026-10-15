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

# Open the example game in the Godot editor
edit: build
    {{godot}} --editor --path {{example}}
