group "default" {
  targets = ["wan-ingress"]
}

target "_common" {
  context    = "."
  dockerfile = "Dockerfile"
  platforms  = ["linux/amd64", "linux/arm64"]
}

target "wan-ingress" {
  inherits = ["_common"]
  target   = "wan-ingress"
  tags     = ["wan-ingress/wan-ingress:local"]
  output   = ["type=oci,dest=dist/wan-ingress.oci.tar"]
}
