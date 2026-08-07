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
          version = "0.3.0";
          source = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              let base = builtins.baseNameOf path;
              in !builtins.elem base [ ".git" ".direnv" "result" ];
          };
          pivbCore = pkgs.buildGoModule {
            pname = "pivb";
            inherit version;
            src = source;
            # Dependencies are checked in so sandboxed builds never need a Go proxy.
            vendorHash = null;
            subPackages = [ "cmd/pivb" ];
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.pcsclite ];
            ldflags = [
              "-s"
              "-w"
              "-X github.com/xlfe/pivb/internal/version.Value=${version}"
            ];
            checkPhase = ''
              runHook preCheck
              go test ./...
              runHook postCheck
            '';
            postInstall = ''
              install -Dm644 systemd/pivb.service "$out/lib/systemd/user/pivb.service"
              substituteInPlace "$out/lib/systemd/user/pivb.service" \
                --replace-fail '@pivb@' "$out/bin/pivb"
            '';
          };
          agentHelper = pkgs.buildGoModule {
            pname = "pivb-agent-subject-token";
            inherit version;
            src = source;
            vendorHash = null;
            subPackages = [ "cmd/pivb-agent-subject-token" ];
            env.CGO_ENABLED = "0";
            doCheck = false; # The main derivation runs the complete module suite.
            nativeBuildInputs = [ pkgs.binutils ];
            preBuild = ''
              if ! pivb_helper_deps="$(go list -deps ./cmd/pivb-agent-subject-token)"; then
                echo "failed to inspect pivb-agent-subject-token dependencies" >&2
                exit 1
              fi
              if printf '%s\n' "$pivb_helper_deps" \
                | grep -Eq '/internal/(config|core|pivsigner|wifapi)$'; then
                echo "pivb-agent-subject-token acquired a forbidden host dependency" >&2
                exit 1
              fi
            '';
            ldflags = [
              "-s"
              "-w"
            ];
            postInstall = ''
              if readelf -l "$out/bin/pivb-agent-subject-token" | grep -q 'INTERP'; then
                echo "pivb-agent-subject-token must be a fully static executable" >&2
                exit 1
              fi
            '';
          };
          pivb = pkgs.symlinkJoin {
            name = "pivb-${version}";
            paths = [ pivbCore agentHelper ];
            meta = {
              description = "Touch-gated networkless YubiKey PIV WIF signer for Google Cloud";
              mainProgram = "pivb";
              platforms = pkgs.lib.platforms.linux;
            };
          };
        in {
          default = pivb;
          inherit pivb;
          pivb-agent-subject-token = agentHelper;
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
