[![Gitpod ready-to-code](https://img.shields.io/badge/Gitpod-ready--to--code-blue?logo=gitpod)](https://gitpod.io/#https://github.com/pavlo-v-chernykh/keystore-go)

# Keystore
A go (golang) implementation of Java [KeyStore][1] encoder/decoder

Take into account that JKS assumes that private keys are PKCS8 encoded.

## Example

For examples explore [examples](examples) directory

## Used by

[cert-manager/cert-manager][2]

[yugabyte/yugabyte-db][3]

[banzaicloud/koperator][4]

[paketo-buildpacks/spring-boot][5]

[paketo-buildpacks/libjvm][6]

[paketo-buildpacks/graalvm][7]

[arangodb/arangosync-client][8]

and [others][9]

## Development

1. Install [go][10]
2. Install [golangci-lint][11]
3. Clone the repo `git clone git@github.com:pavlo-v-chernykh/keystore-go.git`
4. Go to the project dir `cd keystore-go`
5. Run `make`  to format, test and lint

[1]: https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyManagement
[2]: https://github.com/cert-manager/cert-manager
[3]: https://github.com/yugabyte/yugabyte-db
[4]: https://github.com/banzaicloud/koperator
[5]: https://github.com/paketo-buildpacks/spring-boot
[6]: https://github.com/paketo-buildpacks/libjvm
[7]: https://github.com/paketo-buildpacks/graalvm
[8]: https://github.com/arangodb/arangosync-client
[9]: https://github.com/pavlo-v-chernykh/keystore-go/network/dependents
[10]: https://golang.org
[11]: https://github.com/golangci/golangci-lint
