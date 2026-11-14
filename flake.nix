{
  description = "rs-matter development and integration-test environments";

  inputs = {
    # UPDATING
    # `flake.lock` is the pin: `nix flake update nixpkgs` moves it, and the
    # lock file records the exact commit. The stable channel is used because
    # it is well covered by the binary cache, which keeps CI fast.
    # Note: `pkgsCross` is not cached for the stable channel - if it is ever
    #       needed here, switch to a `nixpkgs-unstable` commit from a highly
    #       successful hydra run: https://hydra.nixos.org/jobset/nixpkgs/trunk/evals
    nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # Rust toolchain - pinned. To bump, edit rustVersion below and commit.
        # For nightly: set rustChannel = "nightly" and use a date string,
        #   e.g. rustVersion = "2026-08-01".
        # Available versions: https://rust-lang.github.io/rustup-components-history/
        rustChannel = "stable";
        rustVersion = "1.100.0";

        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        nixpkgsDate =
          let d = nixpkgs.sourceInfo.lastModifiedDate or ""; in
          if d == "" then "unknown"
          else "${builtins.substring 0 4 d}-${builtins.substring 4 2 d}-${builtins.substring 6 2 d}";

        rustToolchain = pkgs.rust-bin.${rustChannel}.${rustVersion}.default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" "rust-analyzer" ];
        };

        # Single source of the Chip integration-test dependencies, mirroring
        # `REQUIRED_TOOLING` / `REQUIRED_PACKAGES` in
        # `xtask/src/itest/common.rs` (which print the Debian/Ubuntu package
        # names via `cargo xtask itest-tooling` / `itest-packages`).
        itestDeps = pkgs: with pkgs; [
          # rust support
          rustToolchain

          # Provide non-privileged execution of `ip` commands
          iproute2
          iptables
          procps
          util-linux

          # connectedhomeip requirements
          bash
          git
          gcc
          glib
          glib.dev
          pkg-config
          cmake
          ninja
          gn
          gobject-introspection.dev
          gobject-introspection.out
          openssl.dev
          dbus
          dbus.dev
          avahi.dev
          unzip
          cairo.dev
          libxcb.dev
          libx11.dev
          xorgproto
          readline.dev
          jre
          libffi.dev
          zap-chip
          protobuf
          abseil-cpp.dev
          abseil-cpp.out
          systemdLibs.dev
          systemdLibs.out
          libevent.dev
          libevent.out
          pcsclite.dev
          pcsclite.lib
          libcap

          ## python support
          # Note: python 3.11 is required due to the deprecation of the `imp` module in newer versions of python.
          python311
          python311Packages.pip
          python311Packages.virtualenv
        ];
      in
      {
        # `cargo xtask itest` drives `connectedhomeip`, whose pigweed
        # bootstrap and CIPD prebuilts assume a standard Linux filesystem
        # layout. `buildFHSEnv` synthesises one, so this env is what the
        # integration tests need on a nix-managed host.
        #
        #   nix run .#fhs                          # interactive shell
        #   nix run .#fhs -- -c 'cargo xtask itest' # one-shot
        #
        # Linux-only: `buildFHSEnv` has no meaning on darwin, and the Chip
        # suites are Linux-only anyway.
        packages = nixpkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          fhs = pkgs.buildFHSEnv {
            name = "rs-matter-test-env";
            runScript = "bash";
            targetPkgs = itestDeps;

            # `buildFHSEnv` seeds `PKG_CONFIG_PATH` with `/usr/lib/pkgconfig`
            # only, and pkg-config's compiled-in default path points at its
            # own store path rather than `/usr`. Modules shipping their `.pc`
            # under `share/pkgconfig` - `systemd.pc`, which `ot-br-posix`
            # checks for, and all of `xorgproto` - are invisible without this.
            profile = ''
              export PKG_CONFIG_PATH="''${PKG_CONFIG_PATH:+$PKG_CONFIG_PATH:}/usr/share/pkgconfig"
            '';
          };
        };

        devShells = {
          # Normal development.
          default = pkgs.mkShell {
            packages = [
              rustToolchain

              pkgs.cargo-expand
              pkgs.git
              pkgs.pkg-config
              pkgs.dbus
              pkgs.avahi.dev
              pkgs.libclang
              pkgs.glibc.dev
            ];

            env = {
              LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
              BINDGEN_EXTRA_CLANG_ARGS = builtins.concatStringsSep " " [
                "-resource-dir=${pkgs.libclang.lib}/lib/clang/${nixpkgs.lib.versions.major pkgs.libclang.version}"
                "-isystem ${pkgs.libclang.lib}/lib/clang/${nixpkgs.lib.versions.major pkgs.libclang.version}/include"
                "-isystem ${pkgs.glibc.dev}/include"
                "-I ${pkgs.avahi.dev}/include"
              ];
            };

            # Only when someone is looking: the banner would otherwise land in
            # `nix develop -c ...` output, direnv reloads, CI logs and editor
            # LSP startup.
            shellHook = ''
              if [ -t 1 ]; then
                echo ""
                cat banner.txt
                echo ""
                echo "═══════════════════════════════════════════════════════════"
                echo "📌 nixpkgs: ${nixpkgs.shortRev or "unknown"} (${nixpkgsDate})"
                echo "🦀 Rust: ${rustChannel} ${rustVersion}"
                echo "───────────────────────────────────────────────────────────"
                echo "💡 For 'cargo xtask itest', use the FHS env: nix run .#fhs"
                echo "💡 To update nixpkgs or rust, consult the project README.md"
                echo "═══════════════════════════════════════════════════════════"
                echo ""
              fi
            '';
          };

        } // nixpkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          # So `nix develop .#fhs` works for muscle memory, though `nix run
          # .#fhs` is the documented entry point: `.env` is an attribute
          # nixpkgs labels interactive-only, while `nix run` goes through the
          # supported wrapper.
          fhs = self.packages.${system}.fhs.env;
        };
      }
    );
}
