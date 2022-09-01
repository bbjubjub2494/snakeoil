# The flake file is the entry point for nix commands
{
  description = "My study of the so-called SPAE cipher";

  # Inputs are how Nix can use code from outside the flake during evaluation.
  inputs.fup.url = "github:gytis-ivaskevicius/flake-utils-plus/v1.3.1";
  inputs.flake-compat.url = "github:edolstra/flake-compat";
  inputs.flake-compat.flake = false;

  # Outputs are the public-facing interface to the flake.
  outputs = inputs @ {
    self,
    fup,
    nixpkgs,
    ...
  }:
    fup.lib.mkFlake {
      inherit self inputs;

      sharedOverlays = [
        (final: _: {
          safeclib = final.callPackage .nix/safeclib.nix {};
        })
      ];

      outputsBuilder = channels: {
        packages.default = channels.nixpkgs.callPackage .nix/package.nix {
          src = self.outPath;
        };
      };
    };
}
