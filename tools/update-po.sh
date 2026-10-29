#!/bin/sh
# Regenerates po/kisnitch.pot from the _() / N_() marks in ui/ and refills
# po/*.po from the upstream Qt .ts files (tools/ts2po.py). Needs xgettext.
set -e
cd "$(dirname "$0")/.."
xgettext --language=C --from-code=UTF-8 --keyword=_ --keyword=N_ \
    --add-comments=TRANSLATORS --no-location --sort-output \
    --package-name=kisnitch --msgid-bugs-address=https://github.com/kiyoshispreclerg/kisnitch/issues \
    -o po/kisnitch.pot ui/*.c
python3 tools/ts2po.py --report "$@"
