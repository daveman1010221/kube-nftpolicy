{
  description = "kube-nftpolicy: Kubernetes NetworkPolicy enforced in nftables, IPv4 only, on each node";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;

        # The binary, with nft on its PATH: it applies its table with `nft -f -`.
        kube-nftpolicy = pkgs.rustPlatform.buildRustPackage {
          pname = "kube-nftpolicy";
          inherit version;
          src = pkgs.lib.cleanSource ./.;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.makeWrapper ];
          # The kernel test applies the script in a network namespace of its own; the build sandbox has no `unshare`,
          # and the test says it skipped.
          postInstall = ''
            wrapProgram $out/bin/kube-nftpolicy --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.nftables ]}
          '';
          meta = {
            description = "Kubernetes NetworkPolicy enforced in nftables, IPv4 only";
            homepage = "https://github.com/daveman1010221/kube-nftpolicy";
            license = pkgs.lib.licenses.asl20;
            platforms = pkgs.lib.platforms.linux;
            mainProgram = "kube-nftpolicy";
          };
        };

        # For clusters whose nodes are not built with Nix: run as a DaemonSet (deploy/).
        image = pkgs.dockerTools.buildLayeredImage {
          name = "kube-nftpolicy";
          tag = version;
          contents = [ kube-nftpolicy pkgs.cacert ];
          config = {
            Entrypoint = [ "${kube-nftpolicy}/bin/kube-nftpolicy" ];
            Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
          };
        };
      in
      {
        packages.default = kube-nftpolicy;
        packages.kube-nftpolicy = kube-nftpolicy;
        packages.image = image;
        checks.default = kube-nftpolicy;
        devShells.default = pkgs.mkShell {
          inputsFrom = [ kube-nftpolicy ];
          packages = [ pkgs.nftables pkgs.clippy pkgs.rustfmt ];
        };
      });
}
