{
  description = "Development environment for Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Используем стабильный Rust с дополнительными компонентами
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust ecosystem
            rustToolchain

            # Системные либы и утилиты, необходимые для сборки сетевых сокетов/С++
            pkg-config
            openssl
            gcc
            gdb
          ];

          # Переменные окружения, чтобы rust-analyzer видел исходники stdlib
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

          shellHook = ''
            echo "🦀 Rust dev environment loaded!"
            rustc --version
          '';
        };
      }
    );
}