/*
 * Note: this file originally auto-generated by mib2c
 * using mfd-data-access.m2c
 */
/* standard Net-SNMP includes */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

/* include our parent header */
#include "jbodDevFanTable.h"


#include "jbodDevFanTable_data_access.h"

/** @ingroup interface
 * @addtogroup data_access data_access: Routines to access data
 *
 * These routines are used to locate the data used to satisfy
 * requests.
 * 
 * @{
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table jbodDevFanTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * INWIN-JBOD-MIB::jbodDevFanTable is subid 4 of product.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.47464.1.2.4, length: 10
*/

/**
 * initialization for jbodDevFanTable data access
 *
 * This function is called during startup to allow you to
 * allocate any resources you need for the data table.
 *
 * @param jbodDevFanTable_reg
 *        Pointer to jbodDevFanTable_registration
 *
 * @retval MFD_SUCCESS : success.
 * @retval MFD_ERROR   : unrecoverable error.
 */
int
jbodDevFanTable_init_data(jbodDevFanTable_registration * jbodDevFanTable_reg)
{
    DEBUGMSGTL(("verbose:jbodDevFanTable:jbodDevFanTable_init_data","called\n"));

    /*
     * TODO:303:o: Initialize jbodDevFanTable data.
     */
    /*
    ***************************************************
    ***             START EXAMPLE CODE              ***
    ***---------------------------------------------***/
    /*
     * if you are the sole writer for the file, you could
     * open it here. However, as stated earlier, we are assuming
     * the worst case, which in this case means that the file is
     * written to by someone else, and might not even exist when
     * we start up. So we can't do anything here.
     */
    /*
    ***---------------------------------------------***
    ***              END  EXAMPLE CODE              ***
    ***************************************************/

    return MFD_SUCCESS;
} /* jbodDevFanTable_init_data */

/**
 * container overview
 *
 */

/**
 * container initialization
 *
 * @param container_ptr_ptr A pointer to a container pointer. If you
 *        create a custom container, use this parameter to return it
 *        to the MFD helper. If set to NULL, the MFD helper will
 *        allocate a container for you.
 *
 *  This function is called at startup to allow you to customize certain
 *  aspects of the access method. For the most part, it is for advanced
 *  users. The default code should suffice for most cases. If no custom
 *  container is allocated, the MFD code will create one for your.
 *
 * @remark
 *  This would also be a good place to do any initialization needed
 *  for you data source. For example, opening a connection to another
 *  process that will supply the data, opening a database, etc.
 */
void
jbodDevFanTable_container_init(netsnmp_container **container_ptr_ptr)
{
    DEBUGMSGTL(("verbose:jbodDevFanTable:jbodDevFanTable_container_init","called\n"));
    
    if (NULL == container_ptr_ptr) {
        snmp_log(LOG_ERR,"bad container param to jbodDevFanTable_container_init\n");
        return;
    }

    /*
     * For advanced users, you can use a custom container. If you
     * do not create one, one will be created for you.
     */
    *container_ptr_ptr = NULL;

} /* jbodDevFanTable_container_init */

/**
 * container shutdown
 *
 * @param container_ptr A pointer to the container.
 *
 *  This function is called at shutdown to allow you to customize certain
 *  aspects of the access method. For the most part, it is for advanced
 *  users. The default code should suffice for most cases.
 *
 *  This function is called before jbodDevFanTable_container_free().
 *
 * @remark
 *  This would also be a good place to do any cleanup needed
 *  for you data source. For example, closing a connection to another
 *  process that supplied the data, closing a database, etc.
 */
void
jbodDevFanTable_container_shutdown(netsnmp_container *container_ptr)
{
    DEBUGMSGTL(("verbose:jbodDevFanTable:jbodDevFanTable_container_shutdown","called\n"));
    
    if (NULL == container_ptr) {
        snmp_log(LOG_ERR,"bad params to jbodDevFanTable_container_shutdown\n");
        return;
    }

} /* jbodDevFanTable_container_shutdown */

/**
 * load initial data
 *
 * TODO:350:M: Implement jbodDevFanTable data load
 *
 * @param container container to which items should be inserted
 *
 * @retval MFD_SUCCESS              : success.
 * @retval MFD_RESOURCE_UNAVAILABLE : Can't access data source
 * @retval MFD_ERROR                : other error.
 *
 *  This function is called to load the index(es) (and data, optionally)
 *  for the every row in the data set.
 *
 * @remark
 *  While loading the data, the only important thing is the indexes.
 *  If access to your data is cheap/fast (e.g. you have a pointer to a
 *  structure in memory), it would make sense to update the data here.
 *  If, however, the accessing the data invovles more work (e.g. parsing
 *  some other existing data, or peforming calculations to derive the data),
 *  then you can limit yourself to setting the indexes and saving any
 *  information you will need later. Then use the saved information in
 *  jbodDevFanTable_row_prep() for populating data.
 *
 * @note
 *  If you need consistency between rows (like you want statistics
 *  for each row to be from the same time frame), you should set all
 *  data here.
 *
 */
int
jbodDevFanTable_container_load(netsnmp_container *container)
{
    jbodDevFanTable_rowreq_ctx *rowreq_ctx;
    size_t                 count = 0;

    /*
     * storage for each column
     */
   long   fanIndex;

    /*
     * temporary storage for index values
     */
        /*
         * fanIndex(1)/INTEGER32/ASN_INTEGER/long(long)//l/a/w/e/R/d/h
         */
   long   fanIndex;

    
    /*
     * this example code is based on a data source that is a
     * text file to be read and parsed.
     */
    FILE *filep;
    char line[MAX_LINE_SIZE];

    DEBUGMSGTL(("verbose:jbodDevFanTable:jbodDevFanTable_container_load","called\n"));

    /*
    ***************************************************
    ***             START EXAMPLE CODE              ***
    ***---------------------------------------------***/
    /*
     * open our data file.
     */
    filep = fopen("/etc/dummy.conf", "r");
    if(NULL ==  filep) {
        return MFD_RESOURCE_UNAVAILABLE;
    }

    /*
    ***---------------------------------------------***
    ***              END  EXAMPLE CODE              ***
    ***************************************************/
    /*
     * TODO:351:M: |-> Load/update data in the jbodDevFanTable container.
     * loop over your jbodDevFanTable data, allocate a rowreq context,
     * set the index(es) [and data, optionally] and insert into
     * the container.
     */
    while( 1 ) {
    /*
    ***************************************************
    ***             START EXAMPLE CODE              ***
    ***---------------------------------------------***/
    /*
     * get a line (skip blank lines)
     */
    do {
        if (!fgets(line, sizeof(line), filep)) {
            /* we're done */
            fclose(filep);
            filep = NULL;
        }
    } while (filep && (line[0] == '\n'));

    /*
     * check for end of data
     */
    if(NULL == filep)
        break;

    /*
     * parse line into variables
     */
    /*
    ***---------------------------------------------***
    ***              END  EXAMPLE CODE              ***
    ***************************************************/

        /*
         * TODO:352:M: |   |-> set indexes in new jbodDevFanTable rowreq context.
         * data context will be set from the param (unless NULL,
         *      in which case a new data context will be allocated)
         */
        rowreq_ctx = jbodDevFanTable_allocate_rowreq_ctx(NULL);
        if (NULL == rowreq_ctx) {
            snmp_log(LOG_ERR, "memory allocation failed\n");
            return MFD_RESOURCE_UNAVAILABLE;
        }
        if(MFD_SUCCESS != jbodDevFanTable_indexes_set(rowreq_ctx
                               , fanIndex
               )) {
            snmp_log(LOG_ERR,"error setting index while loading "
                     "jbodDevFanTable data.\n");
            jbodDevFanTable_release_rowreq_ctx(rowreq_ctx);
            continue;
        }

        /*
         * TODO:352:r: |   |-> populate jbodDevFanTable data context.
         * Populate data context here. (optionally, delay until row prep)
         */
    /*
     * TRANSIENT or semi-TRANSIENT data:
     * copy data or save any info needed to do it in row_prep.
     */
    /*
     * setup/save data for fanDescription
     * fanDescription(2)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/w/e/R/d/H
     */
    /** no mapping */
    /*
     * make sure there is enough space for fanDescription data
     */
    if ((NULL == rowreq_ctx->data.fanDescription) ||
        (rowreq_ctx->data.fanDescription_len <
         (fanDescription_len* sizeof(fanDescription[0])))) {
        snmp_log(LOG_ERR,"not enough space for value (fanDescription)\n");
        return MFD_ERROR;
    }
    rowreq_ctx->data.fanDescription_len = fanDescription_len* sizeof(fanDescription[0]);
    memcpy( rowreq_ctx->data.fanDescription, fanDescription, fanDescription_len* sizeof(fanDescription[0]) );
    
    /*
     * setup/save data for fanStatus
     * fanStatus(3)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/w/e/R/d/H
     */
    /** no mapping */
    /*
     * make sure there is enough space for fanStatus data
     */
    if ((NULL == rowreq_ctx->data.fanStatus) ||
        (rowreq_ctx->data.fanStatus_len <
         (fanStatus_len* sizeof(fanStatus[0])))) {
        snmp_log(LOG_ERR,"not enough space for value (fanStatus)\n");
        return MFD_ERROR;
    }
    rowreq_ctx->data.fanStatus_len = fanStatus_len* sizeof(fanStatus[0]);
    memcpy( rowreq_ctx->data.fanStatus, fanStatus, fanStatus_len* sizeof(fanStatus[0]) );
    
    /*
     * setup/save data for fanValue
     * fanValue(4)/INTEGER32/ASN_INTEGER/long(long)//l/A/w/e/r/d/h
     */
    /** no mapping */
    rowreq_ctx->data.fanValue = fanValue;
    
    /*
     * setup/save data for fanUnit
     * fanUnit(5)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/w/e/R/d/H
     */
    /** no mapping */
    /*
     * make sure there is enough space for fanUnit data
     */
    if ((NULL == rowreq_ctx->data.fanUnit) ||
        (rowreq_ctx->data.fanUnit_len <
         (fanUnit_len* sizeof(fanUnit[0])))) {
        snmp_log(LOG_ERR,"not enough space for value (fanUnit)\n");
        return MFD_ERROR;
    }
    rowreq_ctx->data.fanUnit_len = fanUnit_len* sizeof(fanUnit[0]);
    memcpy( rowreq_ctx->data.fanUnit, fanUnit, fanUnit_len* sizeof(fanUnit[0]) );
    
        
        /*
         * insert into table container
         */
        CONTAINER_INSERT(container, rowreq_ctx);
        ++count;
    }

    /*
    ***************************************************
    ***             START EXAMPLE CODE              ***
    ***---------------------------------------------***/
    if(NULL != filep)
        fclose(filep);
    /*
    ***---------------------------------------------***
    ***              END  EXAMPLE CODE              ***
    ***************************************************/

    DEBUGMSGT(("verbose:jbodDevFanTable:jbodDevFanTable_container_load",
               "inserted %d records\n", count));

    return MFD_SUCCESS;
} /* jbodDevFanTable_container_load */

/**
 * container clean up
 *
 * @param container container with all current items
 *
 *  This optional callback is called prior to all
 *  item's being removed from the container. If you
 *  need to do any processing before that, do it here.
 *
 * @note
 *  The MFD helper will take care of releasing all the row contexts.
 *
 */
void
jbodDevFanTable_container_free(netsnmp_container *container)
{
    DEBUGMSGTL(("verbose:jbodDevFanTable:jbodDevFanTable_container_free","called\n"));

    /*
     * TODO:380:M: Free jbodDevFanTable container data.
     */
} /* jbodDevFanTable_container_free */

/**
 * prepare row for processing.
 *
 *  When the agent has located the row for a request, this function is
 *  called to prepare the row for processing. If you fully populated
 *  the data context during the index setup phase, you may not need to
 *  do anything.
 *
 * @param rowreq_ctx pointer to a context.
 *
 * @retval MFD_SUCCESS     : success.
 * @retval MFD_ERROR       : other error.
 */
int
jbodDevFanTable_row_prep( jbodDevFanTable_rowreq_ctx *rowreq_ctx)
{
    DEBUGMSGTL(("verbose:jbodDevFanTable:jbodDevFanTable_row_prep","called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:390:o: Prepare row for request.
     * If populating row data was delayed, this is the place to
     * fill in the row for this request.
     */

    return MFD_SUCCESS;
} /* jbodDevFanTable_row_prep */

/** @} */