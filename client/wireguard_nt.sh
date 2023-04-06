#!/bin/bash

ldir=$PWD
tmp_dir_path=$ldir/.distfiles
winnt=wireguard-nt.zip
download_file_path=$tmp_dir_path/$winnt
download_url=https://www.wintun.net/builds/wintun-0.14.1.zip
download_sha=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51

function resources_windows(){
  cmd=$1
  arch=$2
  out=$3
  docker run -i --rm -v $PWD:$PWD -w $PWD mstorsjo/llvm-mingw:latest $cmd -O coff -c 65001 -I $tmp_dir_path/wintun/bin/$arch -i resources.rc -o $out
}

mkdir -p $tmp_dir_path
curl -L#o $download_file_path.unverified $download_url
echo "$download_sha  $download_file_path.unverified" | sha256sum -c
mv $download_file_path.unverified $download_file_path

mkdir -p .deps
unzip $download_file_path -d $tmp_dir_path

resources_windows i686-w64-mingw32-windres x86 resources_windows_386.syso
resources_windows aarch64-w64-mingw32-windres arm64 resources_windows_arm64.syso
resources_windows x86_64-w64-mingw32-windres amd64 resources_windows_amd64.syso