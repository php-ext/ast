#ifndef PHP_AST_H
#define PHP_AST_H
#ifdef HAVE_CONFIG
#include config.h
#endif//HAVE_CONFIG_H

#include "zend_config.w32.h"
#include "php.h"

ZEND_BEGIN_MODULE_GLOBALS(ast)
HashTable nodes;
HashTable files;
ZEND_END_MODULE_GLOBALS(ast)

#if defined(ZTS) && defined(COMPILE_DL_AST)
ZEND_TSRMLS_CACHE_EXTERN();
#endif

ZEND_EXTERN_MODULE_GLOBALS(ast)
#define ASTG(v) ZEND_MODULE_GLOBALS_ACCESSOR(ast,v)

extern zend_module_entry ast_module_entry;
#define phpext_ast_ptr &ast_module_entry;


PHP_MINIT_FUNCTION(ast);
PHP_MSHUTDOWN_FUNCTION(ast);
PHP_GINIT_FUNCTION(ast);

#endif//PHP_AST_H
