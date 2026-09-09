# Development Tools

## Alternative Editors

Omarchy ships with [Neovim](https://neovim.io/) by default, but if you'd like something a bit more mainstream and familiar, you can run the Omarchy Menu (`Super + Space`) and see the options under _Install > Editor_. We have VSCode, Cursor, Zed, Sublime Text, Helix, Vim, and Emacs listed there. If you don't find what you're looking for, checkout _Install > Package_, and see if it isn't in an Arch package (and if not, try _Install > AUR_ to check the AUR).

The original `vi` editor is also available out of the box. Run `vi filename` to edit a file in the terminal.

Theme matching is offered for `VSCode`, `Cursor`, `VSCodium`, and `Helix`.

You can set the system-wide default editor under `Setup > Defaults > Editor`.

## Environment

Omarchy supports setting up a whole host of development environments through the _Install > Development_ section of the Omarchy Menu (`Super + Space`). You'll of course find _Ruby on Rails_, but also all three major runtimes for JavaScript (Node.js, Bun, Deno), as well as popular PHP frameworks like Laravel and Symfony. Oh, and there's Go, Rust, Python, Java, Elixir (with Phoenix), .NET, OCaml, Zig, Clojure, and Scala too. It's a very broad selection!

The majority of these environments are managed by [Mise](https://mise.jdx.dev/). It's a tool that lets you install and run multiple versions of a programming language on the same machine. It's like rbenv or rvm for Ruby or virtualenv for Python, but it works for a bunch of different environments.

To install, say, Ruby, you'd run `mise use -g ruby`, which will both install Ruby and set it as the global default. Or, if your project has a .ruby-version file, you can just run `mise i` in the root of that project.

## Podman

[Podman](https://podman.io/) runs containers without a root daemon. Use `podman run`, `podman build`, and `podman-compose up`; the `d` alias also runs Podman. Omarchy includes Podman Compose and [Podman Desktop](https://podman-desktop.io/) to manage your containers and images with `Super + Shift + D`.

The `docker` command is provided by `podman-docker` and forwards to Podman, including in scripts. You can keep using commands such as `docker ps`, `docker build`, and `docker compose up`. Docker Engine is not installed; compatibility follows Podman's supported commands and Compose options.

Development containers run as your user. You do not need sudo or membership in a privileged group. Container images and volumes belong to your account; `sudo podman` has a separate store. The Windows VM uses that root-owned store and asks for authorization when needed.

Install common development databases from _Install > Development > Podman DB_. Their published ports bind to localhost. Containers with a restart policy resume through your user service when you log in. To keep your own services running after logout, enable lingering deliberately with `sudo loginctl enable-linger "$USER"`.


## GitHub CLI

[The GitHub CLI](https://cli.github.com/) let's you authenticate with your GitHub account and clone private repositories using it. It's wired up as one of the lazy-loading mise stubs, so the first time you run `gh`, it installs itself. To authenticate, run `gh auth login`. Then you can checkout private repositories using `gh repo clone org/repo`.

You can also perform a bunch of other GitHub operations using this command. Just run `gh` to see everything that's possible.

There's a lazy-installing stub for `ghui` for managing your pull requests in a TUI too. And [lazygit](https://github.com/jesseduffield/lazygit) is preinstalled, if you'd like to drive git itself from a TUI as well.

## Moving existing containers

During the update, Omarchy moves its development databases into the Podman store of the account running the update. It stops each database, snapshots its image and writable layer, transfers volume data with its numeric ownership, and restores its previous running state in Podman. Windows keeps its existing virtual disk and shared folder. The old Docker data stays on disk as a recovery copy. Restart when the updater asks to clear Docker's temporary networking state.

Custom containers, custom networks, shared volumes, and modified database privileges or resource limits need an explicit transfer using the project's own configuration. The migration identifies these before stopping workloads and stays pending until they are moved. Back up the application data, recreate the project using `podman-compose`, verify its data and behavior, then remove the old Docker containers and retry the update. Docker is removed only after the remaining Omarchy workloads have moved successfully.
