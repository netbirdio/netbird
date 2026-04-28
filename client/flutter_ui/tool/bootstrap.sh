#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

command -v flutter >/dev/null 2>&1 || {
  echo "flutter is not installed"
  exit 1
}

cp "$project_dir/pubspec.yaml" "$tmp_dir/pubspec.yaml"
cp "$project_dir/analysis_options.yaml" "$tmp_dir/analysis_options.yaml"
cp -R "$project_dir/lib" "$tmp_dir/lib"
cp -R "$project_dir/test" "$tmp_dir/test"

flutter create \
  --platforms=windows,macos,linux \
  --project-name=netbird_flutter_ui \
  --org=io.netbird \
  "$project_dir"

cp "$tmp_dir/pubspec.yaml" "$project_dir/pubspec.yaml"
cp "$tmp_dir/analysis_options.yaml" "$project_dir/analysis_options.yaml"
rm -rf "$project_dir/lib"
cp -R "$tmp_dir/lib" "$project_dir/lib"
rm -rf "$project_dir/test"
cp -R "$tmp_dir/test" "$project_dir/test"

cd "$project_dir"
flutter pub get
