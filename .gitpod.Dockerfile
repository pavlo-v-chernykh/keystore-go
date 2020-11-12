FROM gitpod/workspace-full

RUN brew update && brew install golangci-lint

# More information: https://www.gitpod.io/docs/config-docker/
