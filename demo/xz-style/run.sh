#!/usr/bin/env bash
# XRAY launch demo: catching an xz-style library backdoor.
# Needs gcc, bsdtar and Linux Landlock. Everything happens in ./work.
set -u
cd "$(dirname "$0")" || exit 1
here=$PWD
work=${XRAY_DEMO_WORK:-$here/work}
rm -rf "$work" && mkdir -p "$work/root/usr/lib" "$work/root/usr/bin" "$work/pkg"
export XRAY_DEMO_MARK=$work/MARK
read -ra xray <<< "${XRAY:-xray}"

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
run() { local shown=("$@"); [ "${shown[0]}" = "${xray[0]}" ] && shown=(xray "${@:$(( ${#xray[@]} + 1 ))}"); printf '\033[1m$ %s\033[0m\n' "${shown[*]}"; "$@"; local status=$?; printf '\033[2m(exit %s)\033[0m\n' "$status"; return 0; }

package() {  # package VERSION SOURCE
    local dir=$work/pkg/$1
    mkdir -p "$dir/usr/lib"
    gcc -shared -fPIC -O1 -Wl,-soname,liblzdemo.so.5 -o "$dir/usr/lib/liblzdemo.so.5" "$2"
    printf 'pkgname = lzdemo\npkgver = %s\narch = x86_64\npackager = Demo <demo@example.invalid>\n' "$1" > "$dir/.PKGINFO"
    (cd "$dir" && bsdtar --zstd -cf "$work/lzdemo-$1-x86_64.pkg.tar.zst" .PKGINFO usr)
}

say "Build two releases of a compression library: 5.6.0 (clean) and 5.6.1 (backdoored)"
package 5.6.0-1 "$here/lzdemo-clean.c"
package 5.6.1-1 "$here/lzdemo-backdoored.c"
cp "$work/pkg/5.6.0-1/usr/lib/liblzdemo.so.5" "$work/root/usr/lib/"
gcc -O1 -o "$work/root/usr/bin/app" "$here/app.c" -L"$work/root/usr/lib" -l:liblzdemo.so.5 -Wl,-rpath,"$work/root/usr/lib"
cd "$work" || exit 1
run ls

say "1. Before the upgrade: write the app's contract from a traced run, then minimize it"
run "${xray[@]}" contract generate root/usr/bin/app --no-packages --trace -o app.contract -- hello
run "${xray[@]}" contract minimize app.contract -o app.contract -- hello
run grep -v '^#' app.contract

say "2. The release arrives: compare what the two package versions are able to do"
run "${xray[@]}" drift lzdemo-5.6.0-1-x86_64.pkg.tar.zst lzdemo-5.6.1-1-x86_64.pkg.tar.zst --fail-on-gain

say "3. Record both releases in the capability transparency log"
run "${xray[@]}" log add lzdemo-*.pkg.tar.zst --log log.jsonl
run "${xray[@]}" log history lzdemo --log log.jsonl
run "${xray[@]}" log verify --log log.jsonl

say "4. Install the upgrade anyway, then check the app's contract (nothing is run)"
cp pkg/5.6.1-1/usr/lib/liblzdemo.so.5 root/usr/lib/
run "${xray[@]}" contract check app.contract
echo "   (same file name, same API: the contract breaks because the library can now do more)"

say "5. Check what the app really does now, against its contract"
run "${xray[@]}" contract check app.contract --trace -- hello
rm -f "$XRAY_DEMO_MARK"

say "6. Run the app held to its contract"
printf '\033[1m$ xray contract enforce app.contract -- hello\033[0m\n'
"${xray[@]}" contract enforce app.contract -- hello; status=$?
if [ -e "$XRAY_DEMO_MARK" ]; then echo "marker file exists: the payload ran"
elif [ "$status" = 0 ]; then echo "no marker file: the payload was stopped, and the app still did its job"
else echo "the enforced run failed (exit $status)"; fi

say "7. Without the contract, for comparison"
run root/usr/bin/app hello
if [ -e "$XRAY_DEMO_MARK" ]; then echo "marker file exists: $(cat "$XRAY_DEMO_MARK")"; fi
