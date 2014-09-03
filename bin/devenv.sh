#!/bin/bash
#
# Setup or teardown a traxcommon
#

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $DIR/.. &>/dev/null
SOURCE_DIR=$(pwd)
popd &>/dev/null

PY_SRC_DIR=$SOURCE_DIR/lib
PY_DST_DIR=/usr/local/lib/python2.7/dist-packages/traxcommon
SHOW_HELP="no"
UNINSTALL="no"

function help {

	echo "
Setup traxcommon development environment.

Usage: devenv.sh [OPTIONS]

Options:
	-u|--uninstall  Uninstall instead of install
	-h|--help       Show this help
"

}

function install {
	if [ ! -e $PY_DST_DIR ];then
		ln -s $PY_SRC_DIR $PY_DST_DIR
	fi
}

function uninstall {
	unlink $PY_DST_DIR
}

function parse_opts {
  for i in "$@";do

    case $i in
      -u|--uninstall)
        UNINSTALL="yes";
        ;;
      -h|--help)
        SHOW_HELP="yes";
        ;;
      *)
        # Treat unknown opts as positionals
        POSITIONALS=("${POSITIONALS[@]}" "${i}");
        ;;
    esac

  done
}

parse_opts $@

# Capture crtrl-c and exit
function control_c {
  exit 1
}

trap control_c SIGINT

if [[ $SHOW_HELP == "yes" ]]; then
   help
   exit 0
fi

if [[ $UNINSTALL == "yes" ]]; then
   uninstall
   exit 0
fi

install
exit 0
