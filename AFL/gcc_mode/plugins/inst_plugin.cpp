#include <gcc-plugin.h>
#include <tree.h>
#include <gimple.h>
#include <tree-pass.h>
#include <gimple-iterator.h>
#include <stringpool.h>
#include <basic-block.h>
#include <cp/cp-tree.h>
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <functional>

/* Some todo items:
 *	do we need to avoid instrumenting the same statement? Probably not, I do not think the same statement can be processed twice
 * 
 * */

/**
 * When 1 enables verbose printing
 */
#define DEBUG               0


/**
 * Name of the function called to profile code
 */
#define FUNCTION_NAME       "__global_logging"

/**
 * Name of the plugin
 */
#define PLUGIN_NAME         "inst_plugin"

/**
 * Version of this plugin
 */
#define PLUGIN_VERSION      "0.1"


/**
 * Help of this plugin
 */
#define PLUGIN_HELP      "Usage: instrument the program to print accesses to global data"


/**
 * Required GCC version
 */
#define PLUGIN_GCC_BASEV    "8.4.0"

// -----------------------------------------------------------------------------
// GCC PLUGIN SETUP (BASIC INFO / LICENSE / REQUIRED VERSION)
// -----------------------------------------------------------------------------

#define LOG_FILE_ENV	"GLB_VAR_FILE"


int plugin_is_GPL_compatible;

/**
 * Additional information about the plugin. Used by --help and --version
 */
static struct plugin_info inst_plugin_info =
{
  .version  = PLUGIN_VERSION,
  .help     = PLUGIN_HELP,
};

/**
 * Represents the gcc version we need. Used to void using an incompatible plugin 
 */
static struct plugin_gcc_version inst_plugin_ver =
{
  .basever  = PLUGIN_GCC_BASEV,
};

// -----------------------------------------------------------------------------
// GCC EXTERNAL DECLARATION
// -----------------------------------------------------------------------------

/**
 * Takes a tree node and returns the identifier string
 * @see https://gcc.gnu.org/onlinedocs/gccint/Identifiers.html
 */
#define FN_NAME(tree_fun) IDENTIFIER_POINTER (DECL_NAME (tree_fun))

/**
 * Takes a tree node and returns the identifier string length
 * @see https://gcc.gnu.org/onlinedocs/gccint/Identifiers.html
 */
#define FN_NAME_LEN(tree_fun) IDENTIFIER_LENGTH (DECL_NAME (tree_fun))

/**
 * Print GIMPLE statement G to FILE using SPC indentation spaces and FLAGS
 * @note Makes use of pp_gimple_stmt_1
 * @see Declared in gimple-pretty-print.h
 * @see Flags are listed in dumpfile.h
 */
extern void print_gimple_stmt(FILE * file, gimple* g, int spc, dump_flags_t flags);

/**
 * Print tree T, and its successors, on file FILE. FLAGS specifies details to 
 * show in the dump
 * @note Makes use of dump_generic_node
 * @see Declared in tree-pretty-print.h
 * @see Flags are listed in dumpfile.h
 */
extern void print_generic_stmt(FILE* file, tree t, dump_flags_t flags);

/** 
 * The global singleton context aka "g". The name is chosen to be easy to type
 * in a debugger. Represents the 'global state' of GCC
 * 
 * GCC's internal state can be divided into zero or more "parallel universe" of 
 * state; an instance of the class context is one such context of state
 * 
 * @see Declared in context.h
 */
extern gcc::context *g;

// -----------------------------------------------------------------------------
// PLUGIN INSTRUMENTATION LOGICS
// -----------------------------------------------------------------------------


unsigned long long get_log_vid(tree global){

	tree nameid (DECL_NAME(global));

	char info[256];
	char info1[512];

	snprintf(info, 256, "%s-%ld-%s-%d-%s-%s-%s-%s\n", nameid ? IDENTIFIER_POINTER (nameid) : "<unnamed>", int_size_in_bytes(TREE_TYPE (global)), DECL_SOURCE_FILE(global), DECL_SOURCE_LINE(global), FN_NAME(current_function_decl), DECL_FUNCTION_SCOPE_P(global) ? "Yes" : "NO", DECL_FILE_SCOPE_P(global) ? "Yes" : "NO", DECL_THIS_STATIC(global) ? "Yes" : "NO");

	std::string str(info);

	std::hash<std::string> hasher;

	auto vid =  hasher(str); 

	snprintf(info1, 512, "%lu-%s", vid, info);

	char* filename = getenv(LOG_FILE_ENV);

	assert(filename && strlen(filename));

	FILE *fp = fopen(filename, "a");

	assert(fp);

	fprintf(fp, "%s", info1);

	fclose(fp);

#if DEBUG
	dprintf(2, "%s", info1);
#endif
	return vid;
}

//insert call to logging functions
static void instrument_memref(gimple_stmt_iterator *gsi, unsigned long long vid){

	tree proto = build_function_type_list(
			void_type_node,             // return type
			unsigned_type_node,                  // varargs terminator
			NULL_TREE);   

	tree decl = build_fn_decl(FUNCTION_NAME, proto);

	gcall* call = gimple_build_call(decl, 1, build_int_cstu (long_unsigned_type_node, vid));

	gsi_insert_before(gsi, call, GSI_NEW_STMT);

	gsi_next (gsi);
}

// capture store to global data
static void
instrument_store_memref(gimple_stmt_iterator *gsi, tree t, location_t location){

	tree global, type;	
	HOST_WIDE_INT size_in_bytes;
	
	/*
	 * temp variables for inner tree
	 */
	poly_int64 bitsize, bitpos;
	tree offset;
	machine_mode mode;
	int unsignedp, reversep, volatilep = 0;


	global = NULL_TREE;

#if DEBUG
	 int tc (TREE_CODE(t));
	 dprintf(2, "The tree code is %s\n", get_tree_code_name(TREE_CODE(t)));
#endif
	switch (TREE_CODE (t)){
		//the operand is a declaration --> let's check if the declaration is a global varible, if so, record it
		case VAR_DECL:
			global = t;
			break;
		//the operand is something like a.b / a[6] (&a)->mem --> let's get the base object and check if it is a global variable, if so, record it 
		case COMPONENT_REF:
		case ARRAY_REF:
			global = get_inner_reference (t, &bitsize, &bitpos, &offset, &mode, &unsignedp, &reversep, &volatilep);
			return instrument_store_memref(gsi, global, location);
		default:
			break;
	}

	if(global != NULL_TREE && is_global_var(global)){


#if DEBUG
		type = TREE_TYPE (global);
		size_in_bytes = int_size_in_bytes (type);
		tree nameid (DECL_NAME(global));
		const char* name (nameid ? IDENTIFIER_POINTER (nameid) : "<unnamed>");
		dprintf(2, "Found one global variable with name %s, size %ld, declared in file %s at line %d, inside function: %s, inside file: %s, external: %s\n\n", name, size_in_bytes, DECL_SOURCE_FILE(global), DECL_SOURCE_LINE(global), DECL_FUNCTION_SCOPE_P(global) ? "Yes" : "NO", DECL_FILE_SCOPE_P(global) ? "Yes" : "NO", DECL_THIS_STATIC(global) ? "Yes" : "NO");
#endif
		instrument_memref(gsi, get_log_vid(global));
	}
}


//get address-taken operations of global data
static void
instrument_other_memref(gimple_stmt_iterator *gsi, tree t, location_t location){

	tree type, base;	
#if DEBUG
	 int tc (TREE_CODE(t));
	 dprintf(2, "The tree code is %s\n", get_tree_code_name(TREE_CODE(t)));
#endif

	switch (TREE_CODE (t)){
		//the operand takes address of an variable --> let's check if the declaration is global, if so, record it
		case ADDR_EXPR:
			base = get_base_address (TREE_OPERAND (t, 0));

			if(CONSTANT_CLASS_P(base))
				return;
#if DEBUG
			dprintf(2, "The second tree code is %s\n", get_tree_code_name(TREE_CODE(base)));
#endif

			return instrument_store_memref(gsi, base, location);

			break;
		default:
			break;
	}

}


static bool
maybe_instrument_stmt (gimple_stmt_iterator *gsi){

	gimple *stmt = gsi_stmt (*gsi);

	tree ref_expr = NULL_TREE;

	//handle store to global variables
	if (gimple_store_p (stmt))
	{
		ref_expr = gimple_get_lhs(stmt);
		instrument_store_memref(gsi, ref_expr, gimple_location(stmt));
		return true;
	}

	if(is_gimple_call(stmt)){
		unsigned args_num = gimple_call_num_args (stmt);
		for (unsigned i = 0; i < args_num; ++i)
		{
			tree arg = gimple_call_arg (stmt, i);
			instrument_other_memref(gsi, arg, gimple_location(stmt));
		}
		return true;
	}

	if(gimple_assign_single_p (stmt)){
		//handle other cases; let's assume that only the first right-hand operand can be address-taken... yes, this is dangerous
		ref_expr = gimple_assign_rhs1 (stmt);
		instrument_other_memref(gsi, ref_expr, gimple_location(stmt));
		return true;
	}

	return false;
}


/**
 	handle an individual function
 */
static unsigned int insert_instrumentation_stmt(gimple_stmt_iterator *gsi)
{
	gimple *stmt = gsi_stmt (*gsi);

	if (!gimple_clobber_p(stmt)){

#if DEBUG
		dprintf(2, "\n--- Handling a statement in file %s at line %d ---\n", LOCATION_FILE(gimple_location(stmt)), LOCATION_LINE(gimple_location(stmt)));
		print_gimple_stmt(stderr, stmt, 0, TDF_NONE);
#endif		
		maybe_instrument_stmt(gsi);
	}

	return 0;	 

}


/**
 	handle an individual function
 */
static unsigned int insert_instrumentation_fn(function * fun)
{

#if DEBUG
	dprintf(2, "Current function: %s\n",FN_NAME(fun->decl));
#endif

	basic_block bb;

	//iterate each bbl in the current function
	FOR_ALL_BB_FN(bb, fun)
	{
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb (bb); !gsi_end_p (gsi); gsi_next (&gsi))
		{
			insert_instrumentation_stmt(&gsi);
		}

	}

	return 0;
}


/** 
 * Metadata for a pass, non-varying across all instances of a pass
 * @see Declared in tree-pass.h
 * @note Refer to tree-pass for docs about
 */

struct pass_data ins_pass_data =
{
    .type = GIMPLE_PASS,                                    // type of pass
    .name = PLUGIN_NAME,                                    // name of plugin
    .optinfo_flags = OPTGROUP_NONE,                         // no opt dump
    .tv_id = TV_OPTIMIZE,                                       //  tv_id
    .properties_required = 0,                 // entire gimple grammar as input
    .properties_provided = 0,                               // no prop in output
    .properties_destroyed = 0,                              // no prop removed
    .todo_flags_start = 0,                                  // need nothing before
    .todo_flags_finish = 0   // need to update SSA repr after and repair cfg
};

/**
 * Definition of our instrumentation GIMPLE pass
 * @note Extends gimple_opt_pass class
 * @see Declared in tree-pass.h
 */
class ins_gimple_pass : public gimple_opt_pass
{
public:

    /**
     * Constructor
     */
    ins_gimple_pass (const pass_data& data, gcc::context *ctxt) : gimple_opt_pass (data, ctxt) {}

    /**
     * This and all sub-passes are executed only if the function returns true
     * @note Defined in opt_pass father class
     * @see Defined in tree-pass.h
     */ 
    bool gate (function* gate_fun) 
    {
        return true;
    }

    /**
     * This is the code to run when pass is executed
     * @note Defined in opt_pass father class
     * @see Defined in tree-pass.h
     */
    unsigned int execute(function* fun)
    {
	    return insert_instrumentation_fn(fun);
    }
};

// instanciate a new instrumentation GIMPLE pass
ins_gimple_pass inst_pass = ins_gimple_pass(ins_pass_data, g);

// -----------------------------------------------------------------------------
// PLUGIN INITIALIZATION
// -----------------------------------------------------------------------------

/**
 * Initializes the plugin. Returns 0 if initialization finishes successfully. 
 */
int plugin_init(struct plugin_name_args *info, struct plugin_gcc_version *ver)
{
    // new pass that will be registered
    struct register_pass_info pass;

    // this plugin is compatible only with specified base ver
    if (strncmp(inst_plugin_ver.basever, ver->basever, strlen(ver->basever)))
        return 1;

    // tell to GCC some info about this plugin
    register_callback(PLUGIN_NAME, PLUGIN_INFO, NULL, &inst_plugin_info);

    // insert inst pass into the struct used to register the pass
    pass.pass = &inst_pass;

    // and get called after GCC has produced SSA representation  
    pass.reference_pass_name = "cfg";

    // after the first opt pass to be sure opt will not throw away our stuff
    pass.ref_pass_instance_number = 1;

    pass.pos_op = PASS_POS_INSERT_AFTER;

    // add our pass hooking into pass manager
    register_callback(PLUGIN_NAME, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass);

    // everthing has worked
    return 0;
}
