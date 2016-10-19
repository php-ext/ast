#include "php_ast.h"
#include "php_reflection.h"

#include "zend_ast.h"
#include "zend_arena.h"
#include "zend_interfaces.h"
#include "zend_exceptions.h"
#include "zend_language_scanner.h"
#include "zend_language_parser.h" 

#define AST_NO_PROCESS 1

#if PHP_MAJOR_VERSION < 7
# error AST requires PHP version 7 or newer
#endif

#ifdef ENABLE_TRACE
#define TRACE(format, ...) fprintf(stderr, "[%s:%d] " format "\n", __FILE__, __LINE__, __VA_ARGS__)
#else
#define TRACE(format, ...) 
#endif

#ifdef FAST_ZPP
#define AST_PARSE_PARAMETERS_START(min_num_args, max_num_args) \
	zend_error_handling error_handling; \
	zend_replace_error_handling(EH_THROW, NULL, &error_handling);\
	ZEND_PARSE_PARAMETERS_START_EX(0, min_num_args, max_num_args)

#define AST_PARSE_PARAMETERS_END() ZEND_PARSE_PARAMETERS_END_EX(zend_restore_error_handling(&error_handling);return)	
#endif

void(*prev_ast_process)(zend_ast *ast);
extern ZEND_API zend_ast_process_t zend_ast_process;

zend_class_entry* ce_ast = NULL;
zend_class_entry* ce_ast_node = NULL;
zend_class_entry* ce_ast_node_visitor = NULL;
zend_class_entry* ce_ast_decl = NULL;
zend_class_entry* ce_ast_list = NULL;
zend_class_entry* ce_ast_zval = NULL;


typedef struct _ast_tree {
	zend_ast* root;
	zend_arena* arena;
	int refcount;
}ast_tree;

typedef struct _ast_object {
	zend_string* name;
	zend_ast* ast;
	ast_tree* tree;
	zend_object zobj;
}ast_object;

static zend_object_handlers ast_node_handlers;

void(*prev_ast_process)(zend_ast *ast);
extern ZEND_API zend_ast_process_t zend_ast_process;

static inline ast_object* ast_object_from_zend_object(zend_object* zobj) {
	return (ast_object*)((char*)(zobj)-XtOffsetOf(ast_object, zobj));
}

#define Z_AST_OBJ_P(zval_p) ast_object_from_zend_object(Z_OBJ_P(zval_p))
#define AST_OBJ_P(zobj_p) ast_object_from_zend_object(zobj_p)



static inline size_t ast_size(uint32_t children) {
	return sizeof(zend_ast) - sizeof(zend_ast *) + sizeof(zend_ast *) * children;
}
static inline size_t ast_list_size(uint32_t children) {
	return sizeof(zend_ast_list) - sizeof(zend_ast *) + sizeof(zend_ast *) * children;
}


static zend_ast* ast_copy(zend_ast* ast) {
	uint32_t i, cc;

	if (ast == NULL) {
		return NULL;
	}
	if (ast->kind == ZEND_AST_ZNODE) {
		php_error_docref(NULL, E_WARNING, "Unexpected AST_ZNODE");
		return NULL;
	}
	if (ast->kind == ZEND_AST_ZVAL) {
		zend_ast_zval* copy = zend_arena_alloc(&CG(ast_arena), sizeof(zend_ast_zval));
		*copy = *(zend_ast_zval*)ast;
		zval_copy_ctor(&copy->val);
		return (zend_ast*)copy;
	}

	if (zend_ast_is_list(ast)) {
		zend_ast_list* list = zend_ast_get_list(ast);
		zend_ast_list* copy = zend_arena_alloc(&CG(ast_arena), ast_list_size(list->children));
		*copy = *list;
		for (i = 0; i < list->children; i++) {
			copy->child[i] = ast_copy(list->child[i]);
		}
		return (zend_ast*)copy;
	}

	if (ast->kind >(1 << ZEND_AST_SPECIAL_SHIFT) && ast->kind < (1 << ZEND_AST_IS_LIST_SHIFT)) {
		zend_ast_decl* decl = (zend_ast_decl*)ast;
		zend_ast_decl* copy = zend_arena_alloc(&CG(ast_arena), sizeof(zend_ast_decl));
		*copy = *decl;
		for (i = 0; i < 4; i++) {
			copy->child[i] = ast_copy(decl->child[i]);
		}
		return (zend_ast*)copy;
	}

	cc = zend_ast_get_num_children(ast);
	zend_ast* copy = zend_arena_alloc(&CG(ast_arena), ast_size(cc));
	*copy = *ast;
	for (i = 0; i < cc; i++) {
		copy->child[i] = ast_copy(ast->child[i]);
	}
	return copy;
}


/*
Find the first node of the specified kind in the given ast
*/
static zend_ast* ast_find(zend_ast_kind kind, zend_ast* ast) {
	zend_ast* ret = NULL;
	if (ast == NULL) {
		return ret;
	}

	TRACE("ast kind %d", ast->kind);

	if (ast->kind == kind) {
		return ast;
	}
	if (ast->kind == ZEND_AST_ZVAL) {
		return ret;
	}
	uint32_t i, cc = 0;

	if (zend_ast_is_list(ast)) {
		for (i = 0; i < ((zend_ast_list*)ast)->children; i++) {
			ret = ast_find(kind, ((zend_ast_list*)ast)->child[i]);
			if (ret) {
				return ret;
			}
		}
		return ret;
	}
	if (ast->kind >(1 << ZEND_AST_SPECIAL_SHIFT) && ast->kind < (1 << ZEND_AST_IS_LIST_SHIFT)) {
		for (i = 0; i < 4; i++) {
			ret = ast_find(kind, ((zend_ast_decl*)ast)->child[i]);
			if (ret) {
				return ret;
			}
		}
		return ret;
	}

	cc = zend_ast_get_num_children(ast);
	for (i = 0; i < cc; i++) {
		ret = ast_find(kind, ast->child[i]);
		if (ret) {
			return ret;
		}
	}
	return ret;
}

static zend_object* ast_create_object(zend_ast* ast, ast_tree* tree) {
	zend_class_entry* ce = NULL;
	ast_object* node;
	zval zv;
	zval* pzv;

	if (ast == NULL) {
		return NULL;
	}

	ZEND_ASSERT(ast != NULL);
	ZEND_ASSERT(tree != NULL);
	if (zend_hash_index_exists(&ASTG(nodes), (zend_ulong)ast)) {
		pzv = zend_hash_index_find(&ASTG(nodes), (zend_ulong)ast);
		if (pzv) {
			return Z_OBJ_P(pzv);
		}
	}

	TRACE("creating ast object for %I64d", (zend_ulong)ast);

	if (ast->kind == ZEND_AST_ZVAL) {
		ce = ce_ast_zval;
	}

	if (!ce && zend_ast_is_list(ast)) {
		ce = ce_ast_list;
	}

	if (!ce && (ast->kind > (1 << ZEND_AST_SPECIAL_SHIFT) && ast->kind < (1 << ZEND_AST_IS_LIST_SHIFT))) {
		ce = ce_ast_decl;
	}

	if (!ce) {
		ce = ce_ast_node;
	}

	object_init_ex(&zv, ce);

	node = Z_AST_OBJ_P(&zv);
	node->ast = ast;
	node->tree = tree;
	tree->refcount++;

	zend_hash_index_add(&ASTG(nodes), (zend_ulong)ast, &zv);
	return Z_OBJ(zv);
}

#define RETURN_AST_OBJ(ast,tree) \
			RETVAL_OBJ(ast_create_object(ast,tree));\
			Z_ADDREF_P(return_value); \
			return

static zend_object* ast_parse_file(zend_string* filename, zend_long opts) {
	zend_file_handle file_handle;
	zend_lex_state lex_state;
	ast_tree* tree;
	zval* hash;
	zval* pzv;
	if (zend_hash_index_exists(&ASTG(files), ZSTR_HASH(filename))) {
		hash = zend_hash_index_find(&ASTG(files), ZSTR_HASH(filename));
		if (zend_hash_index_exists(&ASTG(nodes), Z_LVAL_P(hash))) {
			pzv = zend_hash_index_find(&ASTG(nodes), Z_LVAL_P(hash));
			if (pzv) {
				return Z_OBJ_P(pzv);
			}
			zend_hash_index_del(&ASTG(files), ZSTR_HASH(filename));
		}
	}

	TRACE("parsing file '%s'", ZSTR_VAL(filename));

	if (zend_stream_open(ZSTR_VAL(filename), &file_handle) == FAILURE) {
		return NULL;
	}
	if (open_file_for_scanning(&file_handle) == FAILURE) {
		zend_destroy_file_handle(&file_handle);
		return NULL;
	}

	zend_save_lexical_state(&lex_state);
	CG(ast) = NULL;
	CG(ast_arena) = zend_arena_create(1024 * 32);

	if (zendparse() != 0) {
		zend_ast_destroy(CG(ast));
		zend_arena_destroy(CG(ast_arena));
		CG(ast) = NULL;
		CG(ast_arena) = NULL;
		zend_restore_lexical_state(&lex_state);
		zend_destroy_file_handle(&file_handle);
		return NULL;
	}

	if (zend_ast_process && !(opts&AST_NO_PROCESS)) {
		(prev_ast_process) ? prev_ast_process(CG(ast)) : zend_ast_process(CG(ast));
	}

	tree = emalloc(sizeof(ast_tree));
	tree->arena = CG(ast_arena);
	tree->refcount = 0;
	tree->root = CG(ast);

	CG(ast) = NULL;
	CG(ast_arena) = NULL;
	zend_restore_lexical_state(&lex_state);
	zend_destroy_file_handle(&file_handle);

	hash = emalloc(sizeof(zval));
	ZVAL_LONG(hash, (zend_ulong)tree->root);
	zend_hash_index_add(&ASTG(files), ZSTR_HASH(filename), hash);
	efree(hash);

	return ast_create_object(tree->root, tree);
}

static void ast_process(zend_ast* ast) {
	ZEND_ASSERT(ast == CG(ast));
	zend_lex_state lex_state;
	zend_arena* prev_arena;
	ast_tree* tree;
	zval hash;

	zend_save_lexical_state(&lex_state);

	if (!zend_hash_index_exists(&ASTG(files), ZSTR_HASH(lex_state.filename))) {
		prev_arena = CG(ast_arena);
		CG(ast_arena) = zend_arena_create(1024 * 32);

		tree = emalloc(sizeof(ast_tree));
		tree->arena = CG(ast_arena);
		tree->refcount = 0;
		tree->root = ast_copy(CG(ast));

		ast_create_object(tree->root, tree);

		ZVAL_LONG(&hash, (zend_ulong)tree->root);
		zend_hash_index_add(&ASTG(files), ZSTR_HASH(lex_state.filename), &hash);

		CG(ast_arena) = prev_arena;
	}
	zend_restore_lexical_state(&lex_state);

	if (prev_ast_process) {
		prev_ast_process(ast);
	}

}

static zend_object* ast_node_create(zend_class_entry* ce) {
	ast_object* node;
	zend_object* zobj;

	node = ecalloc(1, sizeof(ast_object) + zend_object_properties_size(ce));

	zobj = &node->zobj;
	zend_object_std_init(zobj, ce);
	zobj->handlers = &ast_node_handlers;
	return zobj;
}

static void ast_node_dtor(zend_object* zobj) {
	//prevent nodes to be freed until 
	//zend_objects_store_free_object_storage is executed during shutdown
	if (GC_REFCOUNT(zobj) == 1) {
		GC_REFCOUNT(zobj)++;
	}
}

static void ast_node_free(zend_object* zobj) {
	ast_object* node;

	node = AST_OBJ_P(zobj);
	TRACE("freeing ast object for %I64d", (zend_ulong)node->ast);
	//zend_hash_index_(&ASTG(nodes), (zend_ulong)node->ast);
	zend_hash_index_del(&ASTG(nodes), (zend_ulong)node->ast);
	if (node->tree) {
		if (--node->tree->refcount <= 0) {
			ZEND_ASSERT(node->tree->root != NULL);
			ZEND_ASSERT(node->tree->arena != NULL);
			zend_ast_destroy(node->tree->root);
			zend_arena_destroy(node->tree->arena);
			efree(node->tree);
		}
	}
	efree(node);
	zend_object_std_dtor(zobj);
}

// IAstNodeVisitor ////////////////////////////////////////////////////////////////////////////////

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_ast_node_visitor_visit, _IS_BOOL, NULL, 0)
ZEND_ARG_OBJ_INFO(0, node, AstNode, 0)
ZEND_END_ARG_INFO()

zend_function_entry me_ast_node_visitor[] = {
	ZEND_ABSTRACT_ME(IAstNodeVisitor, visit, arginfo_ast_node_visitor_visit)
	ZEND_FE_END
};

int minit_ast_node_visitor(INIT_FUNC_ARGS) {
	zend_class_entry ce;
	INIT_CLASS_ENTRY(ce, "IAstNodeVisitor", me_ast_node_visitor);
	ce_ast_node_visitor = zend_register_internal_interface(&ce);
	return SUCCESS;
}

// AstNode class definition ///////////////////////////////////////////////////////////////////////

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_ast_getnode, IS_OBJECT, "AstNode", 1)
ZEND_ARG_INFO(0, source)
ZEND_ARG_TYPE_INFO(0, lineno, IS_LONG, 1)
ZEND_END_ARG_INFO()

static ZEND_METHOD(Ast, getNode) {
	zval* source;
	zend_string* filename;
	zend_long lineno = 0;
	zend_object* zobj;
	ast_object* node;
	uint32_t i;

	AST_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_ZVAL(source)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(lineno)
		AST_PARSE_PARAMETERS_END();

	//TODO throw invalid argument exception if the first argument is not a string or an abstract function reflection
	// how to we check if the lineno was provided and if not set it to 0

	if (Z_TYPE_P(source) != IS_OBJECT && Z_TYPE_P(source) != IS_STRING) {
		//throw InvalidArgumentException
	}

	if (Z_TYPE_P(source) == IS_OBJECT) {
		//if (!ce || !instanceof_function(Z_OBJCE_P(ret), ce)) {
		//if (!instanceof_function(Z_OBJCE_P(source), )) {
		//	// throw illegal Argument exception
		//}

		zval ret;
		zend_call_method(source, reflection_function_abstract_ptr, NULL, "getfilename", (size_t)11, &ret, 0, NULL, NULL);
		filename = Z_STR(ret);
		zend_call_method(source, reflection_function_abstract_ptr, NULL, "getstartline", (size_t)12, &ret, 0, NULL, NULL);
		lineno = Z_LVAL(ret);
	}
	else {
		filename = Z_STR_P(source);
	}

	TRACE("getting ast node for '%s#%I64d'", ZSTR_VAL(Z_STR_P(source)), lineno);
	zobj = ast_parse_file(filename, 0);
	if (!zobj) {
		RETURN_NULL();
	}

	node = AST_OBJ_P(zobj);
	ZEND_ASSERT(node->ast->kind == ZEND_AST_STMT_LIST);
	for (i = 0; i < ((zend_ast_list*)node->ast)->children; i++) {
		if (((zend_ast*)((zend_ast_list*)node->ast)->child[i])->lineno == lineno) {
			zend_ast* ast = ast_find(ZEND_AST_CLOSURE, ((zend_ast_list*)node->ast)->child[i]);
			RETURN_AST_OBJ(ast, node->tree);
		}
	}
	RETURN_NULL();
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_ast_parsefile, IS_OBJECT, "AstNode", 1)
ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()
static ZEND_METHOD(Ast, parseFile) {
	zend_string* filename;
	zend_object* zobj;

	AST_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(filename)
		AST_PARSE_PARAMETERS_END();

	zobj = ast_parse_file(filename, 0);
	if (!zobj) {
		zend_throw_exception_ex(zend_ce_exception, 0, "Failed to parse file '%s'", ZSTR_VAL(filename));
		return;
	}
	RETURN_OBJ(zobj);
}

zend_function_entry me_ast[] = {
	ZEND_ME(Ast, getNode, arginfo_ast_getnode, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
	ZEND_ME(Ast, parseFile, arginfo_ast_parsefile, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
	ZEND_FE_END
};

static int minit_ast(INIT_FUNC_ARGS) {
	zend_class_entry ce;
	INIT_CLASS_ENTRY(ce, "ast", me_ast);
	ce_ast = zend_register_internal_class(&ce);
	return SUCCESS;
}

// AstNode class definition ///////////////////////////////////////////////////////////////////////

ZEND_BEGIN_ARG_INFO(arginfo_ast_node_accept, 0)
ZEND_ARG_OBJ_INFO(0, visitor, IAstNodeVisitor, 0)
ZEND_END_ARG_INFO()
static ZEND_METHOD(AstNode, accept) {
	ast_object* this;
	zval* visitor;
	zval ret;
	uint32_t i, cc;
	zend_object* zobj;
	zval child;

	AST_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_OBJECT(visitor)
		AST_PARSE_PARAMETERS_END();

	this = Z_AST_OBJ_P(getThis());

	zend_call_method(visitor, NULL, NULL, "visit", (size_t)5, &ret, 1, getThis(), NULL);
	if (Z_TYPE_INFO_P(&ret) == IS_FALSE) {
		return;
	}

	if (this->ast->kind == ZEND_AST_ZVAL) {
		return;
	}

	if (zend_ast_is_list(this->ast)) {
		for (i = 0; i < ((zend_ast_list*)this->ast)->children; i++) {
			zobj = ast_create_object(((zend_ast_list*)this->ast)->child[i], this->tree);
			if (zobj) {
				ZVAL_OBJ(&child, zobj);
				zend_call_method(&child, ce_ast_node, NULL, "accept", (size_t)6, NULL, 1, visitor, NULL);
			}
			ZVAL_NULL(&child);
		}
		return;
	}

	if (this->ast->kind > (1 << ZEND_AST_SPECIAL_SHIFT) && this->ast->kind < (1 << ZEND_AST_IS_LIST_SHIFT)) {
		for (i = 0; i < 4; i++) {
			zobj = ast_create_object(((zend_ast_decl*)this->ast)->child[i], this->tree);
			if (zobj) {
				ZVAL_OBJ(&child, zobj);
				zend_call_method(&child, ce_ast_node, NULL, "accept", (size_t)6, NULL, 1, visitor, NULL);
			}
			ZVAL_NULL(&child);
		}
		return;
	}

	cc = zend_ast_get_num_children(this->ast);
	for (i = 0; i < cc; i++) {
		zobj = ast_create_object(this->ast->child[i], this->tree);
		if (zobj) {
			ZVAL_OBJ(&child, zobj);
			zend_call_method(&child, ce_ast_node, NULL, "accept", (size_t)6, NULL, 1, visitor, NULL);
		}
		ZVAL_NULL(&child);
	}
}

static ZEND_METHOD(AstNode, export) {
	ast_object* this;
	zend_string* zstr;

	this = Z_AST_OBJ_P(getThis());
	zstr = zend_ast_export("", this->ast, "");
	if (!zstr) {
		RETURN_EMPTY_STRING();
	}
	RETURN_STR(zstr);
}

static ZEND_METHOD(AstNode, getKind) {
	ast_object* this;
	this = Z_AST_OBJ_P(getThis());
	RETURN_LONG(this->ast->kind);
}

zend_function_entry me_ast_node[] = {
	ZEND_ME(AstNode, accept, arginfo_ast_node_accept, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
	ZEND_ME(AstNode, export, NULL, ZEND_ACC_PUBLIC)
	ZEND_ME(AstNode, getKind, NULL, ZEND_ACC_PUBLIC)
	ZEND_FE_END
};

static int minit_ast_node(INIT_FUNCTION_ARGS) {
	zend_class_entry ce;

	INIT_CLASS_ENTRY(ce, "AstNode", me_ast_node);
	ce_ast_node = zend_register_internal_class(&ce);
	ce_ast_node->create_object = ast_node_create;

	memcpy(&ast_node_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	ast_node_handlers.offset = XtOffsetOf(ast_object, zobj);
	ast_node_handlers.free_obj = ast_node_free;
	ast_node_handlers.dtor_obj = ast_node_dtor;
	//ast_node_handlers.clone_obj = ast_node_clone;

	return SUCCESS;
}

// AstDecl class definition ///////////////////////////////////////////////////////////////////////
zend_function_entry me_ast_decl[] = {
	ZEND_FE_END
};

static int minit_ast_decl(INIT_FUNC_ARGS) {
	zend_class_entry ce;
	INIT_CLASS_ENTRY(ce, "AstDecl", me_ast_decl);
	ce_ast_decl = zend_register_internal_class_ex(&ce, ce_ast_node);
	return SUCCESS;
}

// AstList class definition ///////////////////////////////////////////////////////////////////////

zend_function_entry me_ast_list[] = {
	ZEND_FE_END
};

static int minit_ast_list(INIT_FUNC_ARGS) {
	zend_class_entry ce;
	INIT_CLASS_ENTRY(ce, "AstList", me_ast_list);
	ce_ast_list = zend_register_internal_class_ex(&ce, ce_ast_node);
	return SUCCESS;
}

// AstZval class definition ///////////////////////////////////////////////////////////////////////

zend_function_entry me_ast_zval[] = {
	ZEND_FE_END
};

static int minit_ast_zval(INIT_FUNC_ARGS) {
	zend_class_entry ce;
	INIT_CLASS_ENTRY(ce, "AstZval", me_ast_zval);
	ce_ast_zval = zend_register_internal_class_ex(&ce, ce_ast_node);
	return SUCCESS;
}

// Ast module definition ///////////////////////////////////////////////////////////////////////

PHP_INI_BEGIN()
PHP_INI_ENTRY("ast.enable_process", "0", PHP_INI_SYSTEM, NULL)
PHP_INI_END()

ZEND_DECLARE_MODULE_GLOBALS(ast);

PHP_MINIT_FUNCTION(ast) {

	REGISTER_INI_ENTRIES();

	/*special nodes*/
	REGISTER_MAIN_LONG_CONSTANT("AST_ZVAL", ZEND_AST_ZVAL, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_ZNODE", ZEND_AST_ZNODE, CONST_PERSISTENT | CONST_CS);

	/*declaration nodes*/
	REGISTER_MAIN_LONG_CONSTANT("AST_FUNC_DECL", ZEND_AST_FUNC_DECL, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CLOSURE", ZEND_AST_CLOSURE, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_METHOD", ZEND_AST_METHOD, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CLASS", ZEND_AST_CLASS, CONST_PERSISTENT | CONST_CS);

	/*list nodes*/
	REGISTER_MAIN_LONG_CONSTANT("AST_ARG_LIST", ZEND_AST_ARG_LIST, CONST_PERSISTENT | CONST_CS);
#if PHP_VERSION_ID < 70100
	REGISTER_MAIN_LONG_CONSTANT("AST_LIST", ZEND_AST_LIST, CONST_PERSISTENT | CONST_CS);
#endif
	REGISTER_MAIN_LONG_CONSTANT("AST_ARRAY", ZEND_AST_ARRAY, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_ENCAPS_LIST", ZEND_AST_ENCAPS_LIST, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_EXPR_LIST", ZEND_AST_EXPR_LIST, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_STMT_LIST", ZEND_AST_STMT_LIST, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_IF", ZEND_AST_IF, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_SWITCH_LIST", ZEND_AST_SWITCH_LIST, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CATCH_LIST", ZEND_AST_CATCH_LIST, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_PARAM_LIST", ZEND_AST_PARAM_LIST, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CLOSURE_USES", ZEND_AST_CLOSURE_USES, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_PROP_DECL", ZEND_AST_PROP_DECL, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CONST_DECL", ZEND_AST_CONST_DECL, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CLASS_CONST_DECL", ZEND_AST_CLASS_CONST_DECL, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_NAME_LIST", ZEND_AST_NAME_LIST, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_TRAIT_ADAPTATIONS", ZEND_AST_TRAIT_ADAPTATIONS, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_USE", ZEND_AST_USE, CONST_PERSISTENT | CONST_CS);

	/*0 child nodes*/
	REGISTER_MAIN_LONG_CONSTANT("AST_MAGIC_CONST", ZEND_AST_MAGIC_CONST, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_TYPE", ZEND_AST_TYPE, CONST_PERSISTENT | CONST_CS);

	/*1 child nodes*/
	REGISTER_MAIN_LONG_CONSTANT("AST_VAR", ZEND_AST_VAR, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CONST", ZEND_AST_CONST, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_UNPACK", ZEND_AST_UNPACK, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_UNARY_PLUS", ZEND_AST_UNARY_PLUS, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_UNARY_MINUS", ZEND_AST_UNARY_MINUS, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CAST", ZEND_AST_CAST, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_EMPTY", ZEND_AST_EMPTY, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_ISSET", ZEND_AST_ISSET, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_SILENCE", ZEND_AST_SILENCE, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_SHELL_EXEC", ZEND_AST_SHELL_EXEC, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CLONE", ZEND_AST_CLONE, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_EXIT", ZEND_AST_EXIT, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_PRINT", ZEND_AST_PRINT, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_INCLUDE_OR_EVAL", ZEND_AST_INCLUDE_OR_EVAL, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_UNARY_OP", ZEND_AST_UNARY_OP, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_PRE_INC", ZEND_AST_PRE_INC, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_PRE_DEC", ZEND_AST_PRE_DEC, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_POST_INC", ZEND_AST_POST_INC, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_POST_DEC", ZEND_AST_POST_DEC, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_YIELD_FROM", ZEND_AST_YIELD_FROM, CONST_PERSISTENT | CONST_CS);

	REGISTER_MAIN_LONG_CONSTANT("AST_GLOBAL", ZEND_AST_GLOBAL, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_UNSET", ZEND_AST_UNSET, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_RETURN", ZEND_AST_RETURN, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_LABEL", ZEND_AST_LABEL, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_REF", ZEND_AST_REF, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_HALT_COMPILER", ZEND_AST_HALT_COMPILER, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_ECHO", ZEND_AST_ECHO, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_THROW", ZEND_AST_THROW, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_GOTO", ZEND_AST_GOTO, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_BREAK", ZEND_AST_BREAK, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CONTINUE", ZEND_AST_CONTINUE, CONST_PERSISTENT | CONST_CS);

	/*2 children nodes*/
	REGISTER_MAIN_LONG_CONSTANT("AST_DIM", ZEND_AST_DIM, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_PROP", ZEND_AST_PROP, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_STATIC_PROP", ZEND_AST_STATIC_PROP, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CALL", ZEND_AST_CALL, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CLASS_CONST", ZEND_AST_CLASS_CONST, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_ASSIGN", ZEND_AST_ASSIGN, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_ASSIGN_REF", ZEND_AST_ASSIGN_REF, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_ASSIGN_OP", ZEND_AST_ASSIGN_OP, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_BINARY_OP", ZEND_AST_BINARY_OP, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_GREATER", ZEND_AST_GREATER, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_GREATER_EQUAL", ZEND_AST_GREATER_EQUAL, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_AND", ZEND_AST_AND, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_OR", ZEND_AST_OR, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_ARRAY_ELEM", ZEND_AST_ARRAY_ELEM, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_NEW", ZEND_AST_NEW, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_INSTANCEOF", ZEND_AST_INSTANCEOF, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_YIELD", ZEND_AST_YIELD, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_COALESCE", ZEND_AST_COALESCE, CONST_PERSISTENT | CONST_CS);

	REGISTER_MAIN_LONG_CONSTANT("AST_STATIC", ZEND_AST_STATIC, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_WHILE", ZEND_AST_WHILE, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_DO_WHILE", ZEND_AST_DO_WHILE, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_IF_ELEM", ZEND_AST_IF_ELEM, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_SWITCH", ZEND_AST_SWITCH, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_SWITCH_CASE", ZEND_AST_SWITCH_CASE, CONST_PERSISTENT | CONST_CS);

	REGISTER_MAIN_LONG_CONSTANT("AST_DECLARE", ZEND_AST_DECLARE, CONST_PERSISTENT | CONST_CS);
#if PHP_VERSION_ID < 70100
	REGISTER_MAIN_LONG_CONSTANT("AST_CONST_ELEM", ZEND_AST_CONST_ELEM, CONST_PERSISTENT | CONST_CS);
#endif
	REGISTER_MAIN_LONG_CONSTANT("AST_USE_TRAIT", ZEND_AST_USE_TRAIT, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_TRAIT_PRECEDENCE", ZEND_AST_TRAIT_PRECEDENCE, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_METHOD_REFERENCE", ZEND_AST_METHOD_REFERENCE, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_NAMESPACE", ZEND_AST_NAMESPACE, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_USE_ELEM", ZEND_AST_USE_ELEM, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_TRAIT_ALIAS", ZEND_AST_TRAIT_ALIAS, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_GROUP_USE", ZEND_AST_GROUP_USE, CONST_PERSISTENT | CONST_CS);

	/*3 children nodes*/
	REGISTER_MAIN_LONG_CONSTANT("AST_METHOD_CALL", ZEND_AST_METHOD_CALL, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_STATIC_CALL", ZEND_AST_STATIC_CALL, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CONDITIONAL", ZEND_AST_CONDITIONAL, CONST_PERSISTENT | CONST_CS);

	REGISTER_MAIN_LONG_CONSTANT("AST_TRY", ZEND_AST_TRY, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_CATCH", ZEND_AST_CATCH, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_PARAM", ZEND_AST_PARAM, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_PROP_ELEM", ZEND_AST_PROP_ELEM, CONST_PERSISTENT | CONST_CS);
#if PHP_VERSION_ID >= 70100
	REGISTER_MAIN_LONG_CONSTANT("AST_CONST_ELEM", ZEND_AST_CONST_ELEM, CONST_PERSISTENT | CONST_CS);
#endif

	/*4 children nodes*/
	REGISTER_MAIN_LONG_CONSTANT("AST_FOR", ZEND_AST_FOR, CONST_PERSISTENT | CONST_CS);
	REGISTER_MAIN_LONG_CONSTANT("AST_FOREACH", ZEND_AST_FOREACH, CONST_PERSISTENT | CONST_CS);

	if (INI_BOOL("ast.enable_process")) {
		prev_ast_process = zend_ast_process;
		zend_ast_process = ast_process;
	}

	return (minit_ast(INIT_FUNC_ARGS_PASSTHRU) == SUCCESS &&
		minit_ast_node(INIT_FUNC_ARGS_PASSTHRU) == SUCCESS &&
		minit_ast_decl(INIT_FUNC_ARGS_PASSTHRU) == SUCCESS &&
		minit_ast_list(INIT_FUNC_ARGS_PASSTHRU) == SUCCESS &&
		minit_ast_zval(INIT_FUNC_ARGS_PASSTHRU) == SUCCESS &&
		minit_ast_node_visitor(INIT_FUNC_ARGS_PASSTHRU) == SUCCESS) ? SUCCESS : FAILURE;
};

PHP_GINIT_FUNCTION(ast) {
#if defined(COMPILE_DL_AST) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	zend_hash_init(&ast_globals->nodes, 32, NULL, NULL, 1);
	zend_hash_init(&ast_globals->files, 32, NULL, NULL, 1);

}


PHP_MSHUTDOWN_FUNCTION(ast) {
	if (prev_ast_process) {
		zend_ast_process = prev_ast_process;
	}
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
};

zend_module_entry ast_module_entry = {
	STANDARD_MODULE_HEADER,
	"ast",
	NULL, /* Functions */
	PHP_MINIT(ast),
	PHP_MSHUTDOWN(ast), /* MSHUTDOWN */
	NULL, /* RINIT */
	NULL, /* RSHUTDOWN */
	NULL, /* MINFO */
	"1.0.0-dev",
	PHP_MODULE_GLOBALS(ast),
	PHP_GINIT(ast), //GINIT
	NULL, /*GSHUTDOWN*/
	NULL, /*RPOSTSHUTDOWN*/
	STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_AST
ZEND_GET_MODULE(ast)
#endif