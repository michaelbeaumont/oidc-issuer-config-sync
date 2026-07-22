# OIDC issuer config sync

Sync the Kubernetes issuer configuration (`/.well-known/openid-configuration` and `/openid/v1/jwks`)
from one cluster to another and serve it in the other cluster.

It takes advantage of the mainline DHT to transfer the public configuration.
