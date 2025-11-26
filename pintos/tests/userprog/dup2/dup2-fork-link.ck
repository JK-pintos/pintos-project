# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [
<<'EOF',
(dup2-fork-link) open "sample.txt"
(dup2-fork-link) set offset to 5
(dup2-fork-link) dup2 to 30
(dup2-fork-link) child read dup fd
(dup2-fork-link) wait child
EOF
,<<'EOF',
(dup2-fork-link) open "sample.txt"
(dup2-fork-link) set offset to 5
(dup2-fork-link) dup2 to 30
(dup2-fork-link) wait child
(dup2-fork-link) child read dup fd
EOF
]);
pass;
