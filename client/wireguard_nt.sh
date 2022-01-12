#!/bin/bash
ldir=$PWD
dirpath=$ldir/.distfiles
winnt=wireguard-nt.zip
downloadfilepath=$dirpath/$winnt
function download() {

  mkdir -p $dirpath
  curl -L#o $downloadfilepath.unverified $1
  echo "$2  $downloadfilepath.unverified" | sha256sum -c
  mv $downloadfilepath.unverified $downloadfilepath
}
function extract(){
	mkdir -p .deps
	unzip $downloadfilepath -d .deps
}
function resources_windows(){
  cmd=$1
  arch=$2
  out=$3
  docker run -i --rm -v $PWD:$PWD -w $PWD mstorsjo/llvm-mingw:latest $cmd -O coff -c 65001 -I .deps/wireguard-nt/bin/$arch -i resources.rc -o $out
}

download https://download.wireguard.com/wireguard-nt/wireguard-nt-0.10.1.zip 772c0b1463d8d2212716f43f06f4594d880dea4f735165bd68e388fc41b81605

extract

resources_windows i686-w64-mingw32-windres x86 resources_windows_386.syso
resources_windows aarch64-w64-mingw32-windres arm64 resources_windows_arm64.syso
resources_windows x86_64-w64-mingw32-windres amd64 resources_windows_amd64.syso

exit 0
