dnl $Id$
dnl config.m4 for extension ast

PHP_ARG_ENABLE(ast, enable ast support,
[  --disable-ast       Disable ast support], yes)

if test "$PHP_AST" != "no"; then
  PHP_NEW_EXTENSION(ast, ast.c, $ext_shared)
fi