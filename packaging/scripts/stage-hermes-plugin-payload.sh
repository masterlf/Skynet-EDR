#!/usr/bin/env sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 SOURCE_PLUGIN_DIR DEST_PLUGIN_DIR" >&2
  exit 2
fi

SOURCE_DIR=${1%/}
DEST_DIR=${2%/}

if [ -L "$SOURCE_DIR" ]; then
  echo "refusing symlink source plugin directory: $SOURCE_DIR" >&2
  exit 1
fi
if [ ! -d "$SOURCE_DIR" ]; then
  echo "source plugin directory is missing: $SOURCE_DIR" >&2
  exit 1
fi

case "$DEST_DIR" in
  ''|'.'|'/' )
    echo "refusing unsafe destination plugin directory: $DEST_DIR" >&2
    exit 1
    ;;
esac

if [ -e "$DEST_DIR" ] || [ -L "$DEST_DIR" ]; then
  echo "refusing existing destination plugin directory: $DEST_DIR" >&2
  exit 1
fi

check_source_parent_dirs() {
  rel_dir=$(dirname "$1")
  if [ "$rel_dir" = "." ]; then
    return 0
  fi

  current_dir="$SOURCE_DIR"
  remaining_dir="$rel_dir"
  while [ -n "$remaining_dir" ]; do
    case "$remaining_dir" in
      */*)
        component=${remaining_dir%%/*}
        remaining_dir=${remaining_dir#*/}
        ;;
      *)
        component=$remaining_dir
        remaining_dir=''
        ;;
    esac

    case "$component" in
      ''|'.'|'..')
        echo "refusing unsafe source directory component: $component" >&2
        exit 1
        ;;
    esac

    current_dir="$current_dir/$component"
    if [ -L "$current_dir" ]; then
      echo "refusing symlink source directory: $current_dir" >&2
      exit 1
    fi
    if [ ! -d "$current_dir" ]; then
      echo "missing source directory: $current_dir" >&2
      exit 1
    fi
  done
}

copy_allowed_file() {
  rel_path="$1"
  src_path="$SOURCE_DIR/$rel_path"
  dst_path="$DEST_DIR/$rel_path"

  case "$rel_path" in
    /*|../*|*/../*|*'/..')
      echo "refusing unsafe payload path: $rel_path" >&2
      exit 1
      ;;
  esac

  if [ -L "$src_path" ]; then
    echo "refusing symlink source file: $src_path" >&2
    exit 1
  fi
  check_source_parent_dirs "$rel_path"
  if [ ! -f "$src_path" ]; then
    echo "missing or non-regular source file: $src_path" >&2
    exit 1
  fi

  case "$dst_path" in
    "$DEST_DIR"/*) ;;
    *)
      echo "refusing destination outside staging path: $dst_path" >&2
      exit 1
      ;;
  esac

  install -d "$(dirname "$dst_path")"
  install -m 0644 "$src_path" "$dst_path"
}

install -d "$(dirname "$DEST_DIR")"
mkdir "$DEST_DIR"

copy_allowed_file 'plugin.yaml'
copy_allowed_file '__init__.py'
copy_allowed_file 'README.md'
copy_allowed_file 'dashboard/manifest.json'
copy_allowed_file 'dashboard/plugin.js'
copy_allowed_file 'dashboard/plugin_api.py'
copy_allowed_file 'desktop/plugin.js'
