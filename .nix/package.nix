{
  stdenv,
  src,
  unzip,
  mpir,
  gmp,
  safeclib,
}:
stdenv.mkDerivation {
  name = "spae-lib";

  inherit src;

  buildInputs = [gmp mpir safeclib];
}
