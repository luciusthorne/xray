TERMUX_PKG_HOMEPAGE=https://github.com/luciusthorne/xray
TERMUX_PKG_DESCRIPTION="Read the code of any command: its files, functions, call graph and what it can do, with evidence"
TERMUX_PKG_LICENSE="Apache-2.0"
TERMUX_PKG_MAINTAINER="@luciusthorne"
TERMUX_PKG_VERSION="1.5.0"
TERMUX_PKG_SRCURL=https://github.com/luciusthorne/xray/releases/download/v${TERMUX_PKG_VERSION}/xray_trust-${TERMUX_PKG_VERSION}.tar.gz
TERMUX_PKG_SHA256=e374a6a80e5965ef10ccb116c1301a34e6d8ab97cdfb3e45563c5838ae575cb9
TERMUX_PKG_AUTO_UPDATE=true
TERMUX_PKG_DEPENDS="binutils, file, python"
TERMUX_PKG_RECOMMENDS="nodejs, strace"
TERMUX_PKG_SUGGESTS="git, ruby"
TERMUX_PKG_PYTHON_COMMON_BUILD_DEPS="setuptools>=77, wheel"
TERMUX_PKG_BUILD_IN_SRC=true
TERMUX_PKG_PLATFORM_INDEPENDENT=true

termux_step_make() {
	echo Skipping make step...
}
