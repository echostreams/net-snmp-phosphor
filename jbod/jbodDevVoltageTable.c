/*
 * Note: this file originally auto-generated by mib2c
 * using mfd-top.m2c
 */
/** \page MFD helper for jbodDevVoltageTable
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
#include "jbodDevVoltageTable.h"

#include <net-snmp/agent/mib_modules.h>

#include "jbodDevVoltageTable_interface.h"

const oid jbodDevVoltageTable_oid[] = { JBODDEVVOLTAGETABLE_OID };
const int jbodDevVoltageTable_oid_size = OID_LENGTH(jbodDevVoltageTable_oid);

    jbodDevVoltageTable_registration  jbodDevVoltageTable_user_context;

void initialize_table_jbodDevVoltageTable(void);
void shutdown_table_jbodDevVoltageTable(void);


/**
 * Initializes the jbodDevVoltageTable module
 */
void
init_jbodDevVoltageTable(void)
{
    DEBUGMSGTL(("verbose:jbodDevVoltageTable:init_jbodDevVoltageTable","called\n"));

    /*
     * TODO:300:o: Perform jbodDevVoltageTable one-time module initialization.
     */
     
    /*
     * here we initialize all the tables we're planning on supporting
     */
    if (should_init("jbodDevVoltageTable"))
        initialize_table_jbodDevVoltageTable();

} /* init_jbodDevVoltageTable */

/**
 * Shut-down the jbodDevVoltageTable module (agent is exiting)
 */
void
shutdown_jbodDevVoltageTable(void)
{
    if (should_init("jbodDevVoltageTable"))
        shutdown_table_jbodDevVoltageTable();

}

/**
 * Initialize the table jbodDevVoltageTable 
 *    (Define its contents and how it's structured)
 */
void
initialize_table_jbodDevVoltageTable(void)
{
    jbodDevVoltageTable_registration * user_context;
    u_long flags;

    DEBUGMSGTL(("verbose:jbodDevVoltageTable:initialize_table_jbodDevVoltageTable","called\n"));

    /*
     * TODO:301:o: Perform jbodDevVoltageTable one-time table initialization.
     */

    /*
     * TODO:302:o: |->Initialize jbodDevVoltageTable user context
     * if you'd like to pass in a pointer to some data for this
     * table, allocate or set it up here.
     */
    /*
     * a netsnmp_data_list is a simple way to store void pointers. A simple
     * string token is used to add, find or remove pointers.
     */
    user_context = netsnmp_create_data_list("jbodDevVoltageTable", NULL, NULL);
    
    /*
     * No support for any flags yet, but in the future you would
     * set any flags here.
     */
    flags = 0;
    
    /*
     * call interface initialization code
     */
    _jbodDevVoltageTable_initialize_interface(user_context, flags);
} /* initialize_table_jbodDevVoltageTable */

/**
 * Shutdown the table jbodDevVoltageTable 
 */
void
shutdown_table_jbodDevVoltageTable(void)
{
    /*
     * call interface shutdown code
     */
    _jbodDevVoltageTable_shutdown_interface(&jbodDevVoltageTable_user_context);
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
jbodDevVoltageTable_rowreq_ctx_init(jbodDevVoltageTable_rowreq_ctx *rowreq_ctx,
                           void *user_init_ctx)
{
    DEBUGMSGTL(("verbose:jbodDevVoltageTable:jbodDevVoltageTable_rowreq_ctx_init","called\n"));

    netsnmp_assert(NULL != rowreq_ctx);
    
    /*
     * TODO:210:o: |-> Perform extra jbodDevVoltageTable rowreq initialization. (eg DEFVALS)
     */

    return MFD_SUCCESS;
} /* jbodDevVoltageTable_rowreq_ctx_init */

/**
 * extra context cleanup
 *
 */
void jbodDevVoltageTable_rowreq_ctx_cleanup(jbodDevVoltageTable_rowreq_ctx *rowreq_ctx)
{
    DEBUGMSGTL(("verbose:jbodDevVoltageTable:jbodDevVoltageTable_rowreq_ctx_cleanup","called\n"));

    netsnmp_assert(NULL != rowreq_ctx);
    
    /*
     * TODO:211:o: |-> Perform extra jbodDevVoltageTable rowreq cleanup.
     */
} /* jbodDevVoltageTable_rowreq_ctx_cleanup */

/**
 * pre-request callback
 *
 *
 * @retval MFD_SUCCESS              : success.
 * @retval MFD_ERROR                : other error
 */
int
jbodDevVoltageTable_pre_request(jbodDevVoltageTable_registration * user_context)
{
    DEBUGMSGTL(("verbose:jbodDevVoltageTable:jbodDevVoltageTable_pre_request","called\n"));

    /*
     * TODO:510:o: Perform jbodDevVoltageTable pre-request actions.
     */

    return MFD_SUCCESS;
} /* jbodDevVoltageTable_pre_request */

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
jbodDevVoltageTable_post_request(jbodDevVoltageTable_registration * user_context, int rc)
{
    DEBUGMSGTL(("verbose:jbodDevVoltageTable:jbodDevVoltageTable_post_request","called\n"));

    /*
     * TODO:511:o: Perform jbodDevVoltageTable post-request actions.
     */

    return MFD_SUCCESS;
} /* jbodDevVoltageTable_post_request */


/** @{ */
