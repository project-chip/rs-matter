{ pkgs, lib, config, inputs, ... }:

{
  cachix.enable = false;

  packages = with pkgs; [ 
    git 
    cargo-expand
    pkg-config
    dbus
    avahi.dev
    libclang
    glibc.dev
  ];

  env = {
    LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
    BINDGEN_EXTRA_CLANG_ARGS = [
      "-resource-dir=${pkgs.libclang.lib}/lib/clang/${lib.versions.major pkgs.libclang.version}"
      "-isystem ${pkgs.libclang.lib}/lib/clang/${lib.versions.major pkgs.libclang.version}/include"
      "-isystem ${pkgs.glibc.dev}/include"
      "-I ${pkgs.avahi.dev}/include"
    ];
  };

  languages.rust = {
    enable = true;
    channel = "nightly";
    components = [ "cargo" "rustc" "rust-src" "rustfmt" "clippy"];
  };

  scripts.banner.exec = ''
    cat banner.txt
  '';

  enterShell = ''
    banner
  '';
}
