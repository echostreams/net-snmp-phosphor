/*
 * Note: this file originally auto-generated by mib2c
 * using mfd-top.m2c
 */
/** \page MFD helper for jbodDevDiskTable
 *
 * \section intro Introduction
 * Introductory text.
 *
 */
/* standard Net-SNMP includes */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

/* include our parent header */
#include "jbodDevDiskTable.h"

#include <net-snmp/agent/mib_modules.h>

#include "jbodDevDiskTable_interface.h"

const oid jbodDevDiskTable_oid[] = { JBODDEVDISKTABLE_OID };
const int jbodDevDiskTable_oid_size = OID_LENGTH(jbodDevDiskTable_oid);

    jbodDevDiskTable_registration  jbodDevDiskTable_user_context;

void initialize_table_jbodDevDiskTable(void);
void shutdown_table_jbodDevDiskTable(void);


/**
 * Initializes the jbodDevDiskTable module
 */
void
init_jbodDevDiskTable(void)
{
    DEBUGMSGTL(("verbose:jbodDevDiskTable:init_jbodDevDiskTable","called\n"));

    /*
     * TODO:300:o: Perform jbodDevDiskTable one-time module initialization.
     */
     
    /*
     * here we initialize all the tables we're planning on supporting
     */
    if (should_init("jbodDevDiskTable"))
        initialize_table_jbodDevDiskTable();

} /* init_jbodDevDiskTable */

/**
 * Shut-down the jbodDevDiskTable module (agent is exiting)
 */
void
shutdown_jbodDevDiskTable(void)
{
    if (should_init("jbodDevDiskTable"))
        shutdown_table_jbodDevDiskTable();

}

/**
 * Initialize the table jbodDevDiskTable 
 *    (Define its contents and how it's structured)
 */
void
initialize_table_jbodDevDiskTable(void)
{
    jbodDevDiskTable_registration * user_context;
    u_long flags;

    DEBUGMSGTL(("verbose:jbodDevDiskTable:initialize_table_jbodDevDiskTable","called\n"));

    /*
     * TODO:301:o: Perform jbodDevDiskTable one-time table initialization.
     */

    /*
     * TODO:302:o: |->Initialize jbodDevDiskTable user context
     * if you'd like to pass in a pointer to some data for this
     * table, allocate or set it up here.
     */
    /*
     * a netsnmp_data_list is a simple way to store void pointers. A simple
     * string token is used to add, find or remove pointers.
     */
    user_context = netsnmp_create_data_list("jbodDevDiskTable", NULL, NULL);
    
    /*
     * No support for any flags yet, but in the future you would
     * set any flags here.
     */
    flags = 0;
    
    /*
     * call interface initialization code
     */
    _jbodDevDiskTable_initialize_interface(user_context, flags);
} /* initialize_table_jbodDevDiskTable */

/**
 * Shutdown the table jbodDevDiskTable 
 */
void
shutdown_table_jbodDevDiskTable(void)
{
    /*
     * call interface shutdown code
     */
    _jbodDevDiskTable_shutdown_interface(&jbodDevDiskTable_user_context);
}

/**
 * extra context initialization (eg default values)
 *
 * @param rowreq_ctx    : row request context
 * @param user_init_ctx : void pointer for user (parameter to rowreq_ctx_allocate)
 *
 * @retval MFD_SUCCESS  : no errors
 * @retval MFD_ERROR    : error (context allocate will fail)
 */
int
jbodDevDiskTable_rowreq_ctx_init(jbodDevDiskTable_rowreq_ctx *rowreq_ctx,
                           void *user_init_ctx)
{
    DEBUGMSGTL(("verbose:jbodDevDiskTable:jbodDevDiskTable_rowreq_ctx_init","called\n"));

    netsnmp_assert(NULL != rowreq_ctx);
    
    /*
     * TODO:210:o: |-> Perform extra jbodDevDiskTable rowreq initialization. (eg DEFVALS)
     */

    return MFD_SUCCESS;
} /* jbodDevDiskTable_rowreq_ctx_init */

/**
 * extra context cleanup
 *
 */
void jbodDevDiskTable_rowreq_ctx_cleanup(jbodDevDiskTable_rowreq_ctx *rowreq_ctx)
{
    DEBUGMSGTL(("verbose:jbodDevDiskTable:jbodDevDiskTable_rowreq_ctx_cleanup","called\n"));

    netsnmp_assert(NULL != rowreq_ctx);
    
    /*
     * TODO:211:o: |-> Perform extra jbodDevDiskTable rowreq cleanup.
     */
} /* jbodDevDiskTable_rowreq_ctx_cleanup */

/**
 * pre-request callback
 *
 *
 * @retval MFD_SUCCESS              : success.
 * @retval MFD_ERROR                : other error
 */
int
jbodDevDiskTable_pre_request(jbodDevDiskTable_registration * user_context)
{
    DEBUGMSGTL(("verbose:jbodDevDiskTable:jbodDevDiskTable_pre_request","called\n"));

    /*
     * TODO:510:o: Perform jbodDevDiskTable pre-request actions.
     */

    return MFD_SUCCESS;
} /* jbodDevDiskTable_pre_request */

/**
 * post-request callback
 *
 * Note:
 *   New rows have been inserted into the container, and
 *   deleted rows have been removed from the container and
 *   released.
 *
 * @param user_context
 * @param rc : MFD_SUCCESS if all requests succeeded
 *
 * @retval MFD_SUCCESS : success.
 * @retval MFD_ERROR   : other error (ignored)
 */
int
jbodDevDiskTable_post_request(jbodDevDiskTable_registration * user_context, int rc)
{
    DEBUGMSGTL(("verbose:jbodDevDiskTable:jbodDevDiskTable_post_request","called\n"));

    /*
     * TODO:511:o: Perform jbodDevDiskTable post-request actions.
     */

    return MFD_SUCCESS;
} /* jbodDevDiskTable_post_request */


/** @{ */