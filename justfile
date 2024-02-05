@_default:
    just --list

# Synchronize fossil repository
sync:
    fossil update

# Build project
build:
    cargo build

# Continuously build project
build--:
    watchexec -e rs -- just build

# Run project
run:
    cargo run

# Continuously run project
run--:
    watchexec -e rs -- just run

# List all changes in repository
status:
    fossil status --extra --changed --missing --deleted --added

# Show repository diff
diff path="":
    fossil diff {{path}}

# Run tests
test name="":
    cargo test {{name}} -- --nocapture

# Continuously run tests
test-- name="":
    watchexec -e rs -- just test {{name}}

# Show latest fossil change
show:
    fossil timeline -n 1 --full -v

# Prepare project for publishing
prepare:
    cargo +nightly fmt

# Show whether project needs to be prepared
[no-exit-message]
check:
    cargo +nightly fmt --check

# Search Rust files
[no-exit-message]
rg term:
    rg -trust "{{term}}"

# Search Rust files case insensitively
[no-exit-message]
rgi term:
    rg -trust -i "{{term}}"
