{ pkgs ? import <nixpkgs> {} }:

(pkgs.buildFHSEnv {
	name = "rs-matter-test-env";
    runScript = builtins.getEnv "SHELL";

    targetPkgs = pkgs: with pkgs; [
        # rust support
        rustc
        cargo
        rustfmt
        clippy

        # Provide non-privileged execution of `ip` commands
        iproute2
        iptables

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
        dbus.dev
        avahi.dev
        unzip
        cairo.dev
        readline.dev
        jre
        libffi.dev
        zap-chip

        ## python support
        # Note: python 3.11 is required due to the deprecation of the `imp` module in newer versions of python.
        python311Full
        python311Packages.pip 
        python311Packages.virtualenv
    ];

}).env
