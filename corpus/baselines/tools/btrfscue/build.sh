# btrfscue v0.7 with noble's Go 1.24, offline: the module files of go.sum come from the lock
# group btrfscue-deps, laid out as a GOPROXY directory, and go.sum still checks every one.
# CGO is off, so the binary is static. Run in the guest by guest/job.sh with bash -e.
tar -xJf "$DL/btrfscue/btrfscue_0.7.orig.tar.xz" -C "$SRC"
cd "$SRC/btrfscue-0.7"
export GOPROXY=file://$DL/btrfscue-deps/goproxy GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0
export GOFLAGS=-mod=mod GOPATH=/work/gopath GOCACHE=/work/gocache
go build -trimpath -o "$PREFIX/bin/btrfscue" ./cmd/btrfscue
echo "btrfscue 0.7 (tag v0.7, commit 5d87ef3), $(go version)" > "$PREFIX/VERSION"
