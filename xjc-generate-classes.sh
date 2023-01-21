#!/bin/sh

script_dir="$(dirname "$0")/"
source_dir=${script_dir}/xsd/
target_dir=${script_dir}/src/generated/java/

rm -rf "$target_dir/" || exit 1
mkdir -p "$target_dir" || exit 1

xjc -nv -d "$target_dir" "$source_dir"
