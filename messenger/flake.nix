{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};
    in {
      devShells.default = pkgs.mkShell rec {
        nativeBuildInputs = with pkgs; [
          cmake
          pkg-config
          grpc-tools
          cargo
          rustc
          xdg-desktop-portal
          xdg-desktop-portal-wlr
          xdg-desktop-portal-gtk
          xdg-desktop-portal-hyprland
          zenity
        ];

        buildInputs = with pkgs; [
          xorg.libX11
          xorg.libXrandr
          xorg.libXcursor
          xorg.libXi
          libxkbcommon
          libGL
          fontconfig
          wayland
        ];

        LD_LIBRARY_PATH = nixpkgs.lib.makeLibraryPath buildInputs;
      };
    });
}
