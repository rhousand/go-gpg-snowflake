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

        # For Docker, always build for Linux
        pkgsLinux = import nixpkgs { system = "x86_64-linux"; };

        # Native build for current system
        app = pkgs.buildGoModule {
          pname = "gopgp-secure-exchange";
          version = "1.0.0";
          src = ./.;
          proxyVendor = true;
          vendorHash = "sha256-P5OmmX+bv2TuRJ6vuNE56K0N09TgK4ENDiAU8YtRz/A";
          ldflags = [ "-s" "-w" ];
        };

        # Linux build for container
        appLinux = pkgsLinux.buildGoModule {
          pname = "gopgp-secure-exchange";
          version = "1.0.0";
          src = ./.;
          proxyVendor = true;
          vendorHash = "sha256-P5OmmX+bv2TuRJ6vuNE56K0N09TgK4ENDiAU8YtRz/A";
          ldflags = [ "-s" "-w" ];
        };
      in {
        packages.container = pkgsLinux.dockerTools.buildLayeredImage {
          name = "github.com/rhousand/go-gpg-snowflake";
          tag = "latest";
          contents = [ appLinux pkgsLinux.cacert ];
          config.Cmd = [ "${appLinux}/bin/go-gpg-snowflake" ];
          config.ExposedPorts = { "8443/tcp" = {}; };
        };

        packages.default = app;

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [ go gopls awscli2 ];
        };
      });
}
