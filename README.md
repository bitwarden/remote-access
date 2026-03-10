<p align="center">
  <br>
  <br>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo-light.svg">
    <img alt="Bitwarden Remote Access" src="assets/logo-light.svg" height="60">
  </picture>
  <br>
  <br>
  <br>
</p>


# Remote Access

Remote Access allows users to access credentials from their password manager on remote systems, without exposing their entire vault.
It creates an end-to-end encrypted tunnel between the remote system and the password manager.

Remote Access is an open protocol, CLI tool, and Rust SDK that you can use to implement it directly into agents or custom software. While we at Bitwarden have built it, it's open for any password manager to leverage to further support agentic or automation use cases without exposing your entire vault.

## Installation

### macOS (Apple Silicon)

```shell
curl -L https://github.com/bitwarden/remote-access/releases/latest/download/bw-remote-macos-aarch64.tar.gz | tar xz
sudo mv bw-remote /usr/local/bin/ # Makes it available on PATH
```

### macOS (Intel)

```shell
curl -L https://github.com/bitwarden/remote-access/releases/latest/download/bw-remote-macos-x86_64.tar.gz | tar xz
sudo mv bw-remote /usr/local/bin/ # Makes it available on PATH
```

### Linux (x86_64)

```shell
curl -L https://github.com/bitwarden/remote-access/releases/latest/download/bw-remote-linux-x86_64.tar.gz | tar xz
sudo mv bw-remote /usr/local/bin/ # Makes it available on PATH
```

### Windows (x86_64)

Download [bw-remote-windows-x86_64.zip](https://github.com/bitwarden/remote-access/releases/latest/download/bw-remote-windows-x86_64.zip) from the [latest release](https://github.com/bitwarden/remote-access/releases/latest) and extract it to a directory on your PATH.

### OpenClaw skill

```shell
curl -fsSL "https://raw.githubusercontent.com/bitwarden/remote-access/main/examples/skills/remote-access/SKILL.md" -o ~/.openclaw/skills/remote-access/SKILL.md --create-dirs
```

## Examples

* [OpenClaw skill](examples/skills/remote-access/SKILL.md)
* Automated script requesting an API-token.
* Github Action

## Getting started (cli, bitwarden)

Once you've installed the CLI tool, it can connect to your Bitwarden vault using the Bitwarden CLI.

**Enabling Remote Access for Bitwarden**

The `aac` CLI tool has built-in support for connecting to the Bitwarden CLI. The interactive CLI can be used to unlock your vault (`/bw-unlock`) and create a pairing code that the remote side can use to connect.

```shell
aac listen
```

The interactive CLI will create a pairing code that you can use to establish a connection on the remote side.

**Setting up the remote side**

You can run the remote side interactively (Useful for testing/demonstration) or without interactivity which is useful for agents and automation.

```shell
# interactive mode
aac connect
```

```shell
# Pairing (without interactivity)
aac connect --token <rendezvous-code> --output json

# Fetching credentials (without interactivity)
aac connect --domain example.com --output json
aac connect --domain github.com --output json

# Pair + Fetch in one command (without interactivity)
aac connect --token <psk/rendezvous-code> --domain example.com --output json

# Output:
{"credential":{"notes":null,"password":"alligator5","totp":null,"uri":"https://github.com","username":"example"},"domain":"github.com","success":true}

```

## Contributing

This repo contains multiple building blocks that power Remote Access.

It contains:

* An end-to-end encrypted tunnel, using Noise
* A Rust SDK for establishing a tunnel, sending requests, and responding to them
* A CLI tool for requesting / releasing credentials
* A proxy server for demo/development purposes

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, crate structure, and how to run the project.
