{
  description = "Secure PGP File Exchange API — Go + Snowflake + AWS KMS + Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        app = pkgs.buildGoModule {
          pname = "gopgp-secure-exchange";
          version = "1.0.0";
          src = ./.;
          vendorHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; # will be filled on first build
          CGO_ENABLED = 0;
          ldflags = [ "-s" "-w" ];
        };
      in {
        packages.container = pkgs.dockerTools.buildLayeredImage {
          name = "github.com/rhousand/go-gpg-snowflake";
          tag = "latest";
          contents = [ app pkgs.cacert ];
          config.Cmd = [ "${app}/bin/main" ];
          config.ExposedPorts = { "8443/tcp" = {}; };
        };

        packages.default = app;

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [ go gopls awscli2 ];
        };
      });
}
