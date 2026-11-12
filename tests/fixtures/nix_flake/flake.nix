{
  description = "Tide predictions for Saltmere Harbour";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    tide-model = {
      url = "git+https://git.harbour.test/tide-model";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, tide-model }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-darwin" ] (system: {
      packages.default = nixpkgs.legacyPackages.${system}.hello;
      devShells.default = nixpkgs.legacyPackages.${system}.mkShell { };
    });
}
