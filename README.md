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


# Bitwarden Remote Access

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
curl -fsSL "https://raw.githubusercontent.com/bitwarden/remote-access/instructions/oc-remote-access.md" -o ~/.openclaw/skills/remote-access/SKILL.md --create-dirs
```

## Examples

* [OpenClaw skill](skills/remote-access/SKILL.md)
* Automated script requesting an API-token.
* Github Action

## Getting started (cli, bitwarden)

Once you've installed the CLI tool, it can connect to your Bitwarden vault using the Bitwarden CLI.

```shell
bw-remote listen
```

The interactive CLI will create a pairing code that you can use to establish a connection on the remote side.

**Setting up the remote side**

You can run the remote side interactively (most useful for testing/demonstration) or in "one-shot" mode for single credential requests.

```shell
# interactive mode
bw-remote connect
```

```shell
# one time pairing
bw-remote connect --token <rendevouz-code> --output json

# one shot mode
bw-remote connect --session <sessionId> --domain example.com --output json
bw-remote connect --session <sessionId> --domain github.com --output json

```

## Contributing

This repo contains multiple building blocks that power Remote Access.

It contains:

* An end-to-end encrypted tunnel, using Noise
* A Rust SDK for establishing a tunnel, sending requests, and responding to them
* A CLI tool for requesting / releasing credentials
* A proxy server for demo/development purposes

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, crate structure, and how to run the project.
