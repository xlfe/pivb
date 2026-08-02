{
  description = "pivb — networkless YubiKey PIV Workload Identity Federation signer for Google Cloud";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          pivb = pkgs.buildGoModule {
            pname = "pivb";
            version = "0.2.0";
            src = pkgs.lib.cleanSourceWith {
              src = ./.;
              filter = path: type:
                let base = builtins.baseNameOf path;
                in !builtins.elem base [ ".git" ".direnv" "result" ];
            };
            # Dependencies are checked in so sandboxed builds never need a Go proxy.
            vendorHash = null;
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.pcsclite ];
            ldflags = [
              "-s"
              "-w"
              "-X github.com/xlfe/pivb/internal/version.Value=0.2.0"
            ];
            postInstall = ''
              install -Dm644 systemd/pivb.service $out/lib/systemd/user/pivb.service
              substituteInPlace $out/lib/systemd/user/pivb.service \
                --replace-fail '@pivb@' "$out/bin/pivb"
            '';
            meta = {
              description = "Touch-gated networkless YubiKey PIV WIF signer for Google Cloud";
              mainProgram = "pivb";
              platforms = pkgs.lib.platforms.linux;
            };
          };
        in {
          default = pivb;
          inherit pivb;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.pivb}/bin/pivb";
        };
      });

      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            packages = [ pkgs.go pkgs.pkg-config pkgs.pcsclite pkgs.shellcheck ];
          };
        });
    };
}
