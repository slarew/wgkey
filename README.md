wgkey is a self-contained program that generates a random WireGuard private and
public key.

Compile and run:

```
cc -o wgkey wgkey.c
umask 077
wgkey private public
```

Keys are base64 encoded as per WireGuard convention.
```
cat private public
8PlGPFxq2y6h4D8gOxl/FkWjjGIyI0wx4HxfYCFEaGQ=
U6r5E+63LCCJByb/0KxxsAsdVs5wfZSEZwJINTdNFAw=
```

Should work on macOS and Linux.

Bonus: cross compile with Zig!

```
for target in aarch64-macos x86_64-macos aarch64-linux-musl x86_64-linux-musl i386-linux-musl; do
  echo "target: $target"
  zig cc -target $target -Os -o wgkey-$target wgkey.c
done
```
