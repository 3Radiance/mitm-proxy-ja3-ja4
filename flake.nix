{
  description = "FHS Rust development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        proxyUrl = "http://127.0.0.1:10808";
        fhs = pkgs.buildFHSEnv {
          name = "rust-doh-env";

          targetPkgs = pkgs: with pkgs; [
            # Rust & Cargo
            rustc
            cargo
            rust-analyzer

            # C/C++ & LLVM / Clang
            gcc
            clang
            llvmPackages.libclang

            # Build tools
            cmake
            gnumake
            pkg-config
            ninja
            go

            # System libs
            glibc
            glibc.dev
            openssl
            openssl.dev
            libunwind
            zlib
          ];

          profile = ''
            export HTTP_PROXY="${proxyUrl}"
            export HTTPS_PROXY="${proxyUrl}"
            export http_proxy="${proxyUrl}"
            export https_proxy="${proxyUrl}"
            export ALL_PROXY="${proxyUrl}"
            export all_proxy="${proxyUrl}"

            export RUST_SRC_PATH="${pkgs.rustPlatform.rustLibSrc}"

            export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
            export BINDGEN_EXTRA_CLANG_ARGS="-I${pkgs.glibc.dev}/include"

            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="gcc"
            export RUSTFLAGS="-C linker=gcc"
          '';

          runScript = "zsh";
        };
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [ fhs ];
          shellHook = "exec rust-doh-env";
        };
      }
    );
}