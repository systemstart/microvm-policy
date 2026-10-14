# gsemver: conventional-commit-driven semantic version bumping, used by
# `make release-tag` to compute the next tag. Not packaged in nixpkgs, so it is
# fetched from upstream's prebuilt release tarballs. This is a dev-shell-only
# dependency and never enters the built package.
{
  lib,
  stdenv,
  fetchurl,
}:
let
  version = "0.10.0";

  sources = {
    "x86_64-linux" = {
      url = "https://github.com/arnaud-deprez/gsemver/releases/download/v${version}/gsemver_${version}_linux_amd64.tar.gz";
      hash = "sha256-F1oyytHMSEBZTNWVyxKM6Zua2sJeQjQ3pyyPDxYDk78=";
    };
    "aarch64-linux" = {
      url = "https://github.com/arnaud-deprez/gsemver/releases/download/v${version}/gsemver_${version}_linux_arm64.tar.gz";
      hash = "sha256-PRIp6ti87aoLoKdLWnDSJLUw+uM95olpUB2ILSmtMII=";
    };
    "x86_64-darwin" = {
      url = "https://github.com/arnaud-deprez/gsemver/releases/download/v${version}/gsemver_${version}_darwin_amd64.tar.gz";
      hash = "sha256-BBKey/Gk1gDQ3uKWuBLuPqEYdjBxxVYsBytBFOOygz4=";
    };
    "aarch64-darwin" = {
      url = "https://github.com/arnaud-deprez/gsemver/releases/download/v${version}/gsemver_${version}_darwin_arm64.tar.gz";
      hash = "sha256-kH11CbkodKKWu9Nh3piGrdTAzSOV/o4Q24uzhasQUQU=";
    };
  };

  src = sources.${stdenv.hostPlatform.system} or (throw "gsemver: unsupported system ${stdenv.hostPlatform.system}");
in
stdenv.mkDerivation {
  pname = "gsemver";
  inherit version;

  src = fetchurl { inherit (src) url hash; };

  sourceRoot = ".";
  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall
    install -Dm755 gsemver $out/bin/gsemver
    runHook postInstall
  '';

  meta = {
    description = "Automatic semantic versioning from git history (conventional commits)";
    homepage = "https://github.com/arnaud-deprez/gsemver";
    license = lib.licenses.asl20;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    platforms = builtins.attrNames sources;
    mainProgram = "gsemver";
  };
}
