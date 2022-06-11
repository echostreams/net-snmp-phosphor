/*
 * Note: this file originally auto-generated by mib2c
 * using mfd-data-get.m2c
 */
/* standard Net-SNMP includes */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

/* include our parent header */
#include "jbodDevTemperatureTable.h"


/** @defgroup data_get data_get: Routines to get data
 *
 * TODO:230:M: Implement jbodDevTemperatureTable get routines.
 * TODO:240:M: Implement jbodDevTemperatureTable mapping routines (if any).
 *
 * These routine are used to get the value for individual objects. The
 * row context is passed, along with a pointer to the memory where the
 * value should be copied.
 *
 * @{
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table jbodDevTemperatureTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * INWIN-JBOD-MIB::jbodDevTemperatureTable is subid 2 of product.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.47464.1.2.2, length: 10
*/

/* ---------------------------------------------------------------------
 * TODO:200:r: Implement jbodDevTemperatureTable data context functions.
 */


/**
 * set mib index(es)
 *
 * @param tbl_idx mib index structure
 * @param temperatureIndex_val
 *
 * @retval MFD_SUCCESS     : success.
 * @retval MFD_ERROR       : other error.
 *
 * @remark
 *  This convenience function is useful for setting all the MIB index
 *  components with a single function call. It is assume that the C values
 *  have already been mapped from their native/rawformat to the MIB format.
 */
int
jbodDevTemperatureTable_indexes_set_tbl_idx(jbodDevTemperatureTable_mib_index *tbl_idx, long temperatureIndex_val)
{
    DEBUGMSGTL(("verbose:jbodDevTemperatureTable:jbodDevTemperatureTable_indexes_set_tbl_idx","called\n"));

    /* temperatureIndex(1)/INTEGER32/ASN_INTEGER/long(long)//l/a/w/e/R/d/h */
    tbl_idx->temperatureIndex = temperatureIndex_val;
    

    return MFD_SUCCESS;
} /* jbodDevTemperatureTable_indexes_set_tbl_idx */

/**
 * @internal
 * set row context indexes
 *
 * @param reqreq_ctx the row context that needs updated indexes
 *
 * @retval MFD_SUCCESS     : success.
 * @retval MFD_ERROR       : other error.
 *
 * @remark
 *  This function sets the mib indexs, then updates the oid indexs
 *  from the mib index.
 */
int
jbodDevTemperatureTable_indexes_set(jbodDevTemperatureTable_rowreq_ctx *rowreq_ctx, long temperatureIndex_val)
{
    DEBUGMSGTL(("verbose:jbodDevTemperatureTable:jbodDevTemperatureTable_indexes_set","called\n"));

    if(MFD_SUCCESS != jbodDevTemperatureTable_indexes_set_tbl_idx(&rowreq_ctx->tbl_idx
                                   , temperatureIndex_val
           ))
        return MFD_ERROR;

    /*
     * convert mib index to oid index
     */
    rowreq_ctx->oid_idx.len = sizeof(rowreq_ctx->oid_tmp) / sizeof(oid);
    if(0 != jbodDevTemperatureTable_index_to_oid(&rowreq_ctx->oid_idx,
                                    &rowreq_ctx->tbl_idx)) {
        return MFD_ERROR;
    }

    return MFD_SUCCESS;
} /* jbodDevTemperatureTable_indexes_set */


/*---------------------------------------------------------------------
 * INWIN-JBOD-MIB::jbodDevTemperatureEntry.temperatureDescription
 * temperatureDescription is subid 2 of jbodDevTemperatureEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.47464.1.2.2.1.2
 * Description:
Describe the temperature sensor
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  0      hasdefval 0
 *   readable   1     iscolumn 1     ranges 1      hashint   1
 *   settable   0
 *   hint: 255a
 *
 * Ranges:  0 - 128;
 *
 * Its syntax is SnmpAdminString (based on perltype OCTETSTR)
 * The net-snmp type is ASN_OCTET_STR. The C type decl is char (char)
 * This data type requires a length.  (Max 128)
 */
/**
 * Extract the current value of the temperatureDescription data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param temperatureDescription_val_ptr_ptr
 *        Pointer to storage for a char variable
 * @param temperatureDescription_val_ptr_len_ptr
 *        Pointer to a size_t. On entry, it will contain the size (in bytes)
 *        pointed to by temperatureDescription.
 *        On exit, this value should contain the data size (in bytes).
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
*
 * @note If you need more than (*temperatureDescription_val_ptr_len_ptr) bytes of memory,
 *       allocate it using malloc() and update temperatureDescription_val_ptr_ptr.
 *       <b>DO NOT</b> free the previous pointer.
 *       The MFD helper will release the memory you allocate.
 *
 * @remark If you call this function yourself, you are responsible
 *         for checking if the pointer changed, and freeing any
 *         previously allocated memory. (Not necessary if you pass
 *         in a pointer to static memory, obviously.)
 */
int
temperatureDescription_get( jbodDevTemperatureTable_rowreq_ctx *rowreq_ctx, char **temperatureDescription_val_ptr_ptr, size_t *temperatureDescription_val_ptr_len_ptr )
{
   /** we should have a non-NULL pointer and enough storage */
   netsnmp_assert( (NULL != temperatureDescription_val_ptr_ptr) && (NULL != *temperatureDescription_val_ptr_ptr));
   netsnmp_assert( NULL != temperatureDescription_val_ptr_len_ptr );


    DEBUGMSGTL(("verbose:jbodDevTemperatureTable:temperatureDescription_get","called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

/*
 * TODO:231:o: |-> Extract the current value of the temperatureDescription data.
 * copy (* temperatureDescription_val_ptr_ptr ) data and (* temperatureDescription_val_ptr_len_ptr ) from rowreq_ctx->data
 */
    /*
     * make sure there is enough space for temperatureDescription data
     */
    if ((NULL == (* temperatureDescription_val_ptr_ptr )) ||
        ((* temperatureDescription_val_ptr_len_ptr ) <
         (rowreq_ctx->data.temperatureDescription_len* sizeof(rowreq_ctx->data.temperatureDescription[0])))) {
        /*
         * allocate space for temperatureDescription data
         */
        (* temperatureDescription_val_ptr_ptr ) = malloc(rowreq_ctx->data.temperatureDescription_len* sizeof(rowreq_ctx->data.temperatureDescription[0]));
        if(NULL == (* temperatureDescription_val_ptr_ptr )) {
            snmp_log(LOG_ERR,"could not allocate memory (rowreq_ctx->data.temperatureDescription)\n");
            return MFD_ERROR;
        }
    }
    (* temperatureDescription_val_ptr_len_ptr ) = rowreq_ctx->data.temperatureDescription_len* sizeof(rowreq_ctx->data.temperatureDescription[0]);
    memcpy( (* temperatureDescription_val_ptr_ptr ), rowreq_ctx->data.temperatureDescription, rowreq_ctx->data.temperatureDescription_len* sizeof(rowreq_ctx->data.temperatureDescription[0]) );

    return MFD_SUCCESS;
} /* temperatureDescription_get */

/*---------------------------------------------------------------------
 * INWIN-JBOD-MIB::jbodDevTemperatureEntry.temperatureStatus
 * temperatureStatus is subid 3 of jbodDevTemperatureEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.47464.1.2.2.1.3
 * Description:
Describe the temperature sensor status
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  0      hasdefval 0
 *   readable   1     iscolumn 1     ranges 1      hashint   1
 *   settable   0
 *   hint: 255a
 *
 * Ranges:  0 - 128;
 *
 * Its syntax is SnmpAdminString (based on perltype OCTETSTR)
 * The net-snmp type is ASN_OCTET_STR. The C type decl is char (char)
 * This data type requires a length.  (Max 128)
 */
/**
 * Extract the current value of the temperatureStatus data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param temperatureStatus_val_ptr_ptr
 *        Pointer to storage for a char variable
 * @param temperatureStatus_val_ptr_len_ptr
 *        Pointer to a size_t. On entry, it will contain the size (in bytes)
 *        pointed to by temperatureStatus.
 *        On exit, this value should contain the data size (in bytes).
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
*
 * @note If you need more than (*temperatureStatus_val_ptr_len_ptr) bytes of memory,
 *       allocate it using malloc() and update temperatureStatus_val_ptr_ptr.
 *       <b>DO NOT</b> free the previous pointer.
 *       The MFD helper will release the memory you allocate.
 *
 * @remark If you call this function yourself, you are responsible
 *         for checking if the pointer changed, and freeing any
 *         previously allocated memory. (Not necessary if you pass
 *         in a pointer to static memory, obviously.)
 */
int
temperatureStatus_get( jbodDevTemperatureTable_rowreq_ctx *rowreq_ctx, char **temperatureStatus_val_ptr_ptr, size_t *temperatureStatus_val_ptr_len_ptr )
{
   /** we should have a non-NULL pointer and enough storage */
   netsnmp_assert( (NULL != temperatureStatus_val_ptr_ptr) && (NULL != *temperatureStatus_val_ptr_ptr));
   netsnmp_assert( NULL != temperatureStatus_val_ptr_len_ptr );


    DEBUGMSGTL(("verbose:jbodDevTemperatureTable:temperatureStatus_get","called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

/*
 * TODO:231:o: |-> Extract the current value of the temperatureStatus data.
 * copy (* temperatureStatus_val_ptr_ptr ) data and (* temperatureStatus_val_ptr_len_ptr ) from rowreq_ctx->data
 */
    /*
     * make sure there is enough space for temperatureStatus data
     */
    if ((NULL == (* temperatureStatus_val_ptr_ptr )) ||
        ((* temperatureStatus_val_ptr_len_ptr ) <
         (rowreq_ctx->data.temperatureStatus_len* sizeof(rowreq_ctx->data.temperatureStatus[0])))) {
        /*
         * allocate space for temperatureStatus data
         */
        (* temperatureStatus_val_ptr_ptr ) = malloc(rowreq_ctx->data.temperatureStatus_len* sizeof(rowreq_ctx->data.temperatureStatus[0]));
        if(NULL == (* temperatureStatus_val_ptr_ptr )) {
            snmp_log(LOG_ERR,"could not allocate memory (rowreq_ctx->data.temperatureStatus)\n");
            return MFD_ERROR;
        }
    }
    (* temperatureStatus_val_ptr_len_ptr ) = rowreq_ctx->data.temperatureStatus_len* sizeof(rowreq_ctx->data.temperatureStatus[0]);
    memcpy( (* temperatureStatus_val_ptr_ptr ), rowreq_ctx->data.temperatureStatus, rowreq_ctx->data.temperatureStatus_len* sizeof(rowreq_ctx->data.temperatureStatus[0]) );

    return MFD_SUCCESS;
} /* temperatureStatus_get */

/*---------------------------------------------------------------------
 * INWIN-JBOD-MIB::jbodDevTemperatureEntry.temperatureValue
 * temperatureValue is subid 4 of jbodDevTemperatureEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.47464.1.2.2.1.4
 * Description:
Describe the degree of sensor temperature
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  0      hasdefval 0
 *   readable   1     iscolumn 1     ranges 0      hashint   0
 *   settable   0
 *
 *
 * Its syntax is INTEGER32 (based on perltype INTEGER32)
 * The net-snmp type is ASN_INTEGER. The C type decl is long (long)
 */
/**
 * Extract the current value of the temperatureValue data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param temperatureValue_val_ptr
 *        Pointer to storage for a long variable
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
 */
int
temperatureValue_get( jbodDevTemperatureTable_rowreq_ctx *rowreq_ctx, long * temperatureValue_val_ptr )
{
   /** we should have a non-NULL pointer */
   netsnmp_assert( NULL != temperatureValue_val_ptr );


    DEBUGMSGTL(("verbose:jbodDevTemperatureTable:temperatureValue_get","called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

/*
 * TODO:231:o: |-> Extract the current value of the temperatureValue data.
 * copy (* temperatureValue_val_ptr ) from rowreq_ctx->data
 */
    (* temperatureValue_val_ptr ) = rowreq_ctx->data.temperatureValue;

    return MFD_SUCCESS;
} /* temperatureValue_get */

/*---------------------------------------------------------------------
 * INWIN-JBOD-MIB::jbodDevTemperatureEntry.temperatureUnit
 * temperatureUnit is subid 5 of jbodDevTemperatureEntry.
 * Its status is Current, and its access level is ReadOnly.
 * OID: .1.3.6.1.4.1.47464.1.2.2.1.5
 * Description:
Describe the temperature unit, should be 1/10 Celsius or 1/10 Fahrenheit
 *
 * Attributes:
 *   accessible 1     isscalar 0     enums  0      hasdefval 0
 *   readable   1     iscolumn 1     ranges 1      hashint   1
 *   settable   0
 *   hint: 255a
 *
 * Ranges:  0 - 128;
 *
 * Its syntax is SnmpAdminString (based on perltype OCTETSTR)
 * The net-snmp type is ASN_OCTET_STR. The C type decl is char (char)
 * This data type requires a length.  (Max 128)
 */
/**
 * Extract the current value of the temperatureUnit data.
 *
 * Set a value using the data context for the row.
 *
 * @param rowreq_ctx
 *        Pointer to the row request context.
 * @param temperatureUnit_val_ptr_ptr
 *        Pointer to storage for a char variable
 * @param temperatureUnit_val_ptr_len_ptr
 *        Pointer to a size_t. On entry, it will contain the size (in bytes)
 *        pointed to by temperatureUnit.
 *        On exit, this value should contain the data size (in bytes).
 *
 * @retval MFD_SUCCESS         : success
 * @retval MFD_SKIP            : skip this node (no value for now)
 * @retval MFD_ERROR           : Any other error
*
 * @note If you need more than (*temperatureUnit_val_ptr_len_ptr) bytes of memory,
 *       allocate it using malloc() and update temperatureUnit_val_ptr_ptr.
 *       <b>DO NOT</b> free the previous pointer.
 *       The MFD helper will release the memory you allocate.
 *
 * @remark If you call this function yourself, you are responsible
 *         for checking if the pointer changed, and freeing any
 *         previously allocated memory. (Not necessary if you pass
 *         in a pointer to static memory, obviously.)
 */
int
temperatureUnit_get( jbodDevTemperatureTable_rowreq_ctx *rowreq_ctx, char **temperatureUnit_val_ptr_ptr, size_t *temperatureUnit_val_ptr_len_ptr )
{
   /** we should have a non-NULL pointer and enough storage */
   netsnmp_assert( (NULL != temperatureUnit_val_ptr_ptr) && (NULL != *temperatureUnit_val_ptr_ptr));
   netsnmp_assert( NULL != temperatureUnit_val_ptr_len_ptr );


    DEBUGMSGTL(("verbose:jbodDevTemperatureTable:temperatureUnit_get","called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

/*
 * TODO:231:o: |-> Extract the current value of the temperatureUnit data.
 * copy (* temperatureUnit_val_ptr_ptr ) data and (* temperatureUnit_val_ptr_len_ptr ) from rowreq_ctx->data
 */
    /*
     * make sure there is enough space for temperatureUnit data
     */
    if ((NULL == (* temperatureUnit_val_ptr_ptr )) ||
        ((* temperatureUnit_val_ptr_len_ptr ) <
         (rowreq_ctx->data.temperatureUnit_len* sizeof(rowreq_ctx->data.temperatureUnit[0])))) {
        /*
         * allocate space for temperatureUnit data
         */
        (* temperatureUnit_val_ptr_ptr ) = malloc(rowreq_ctx->data.temperatureUnit_len* sizeof(rowreq_ctx->data.temperatureUnit[0]));
        if(NULL == (* temperatureUnit_val_ptr_ptr )) {
            snmp_log(LOG_ERR,"could not allocate memory (rowreq_ctx->data.temperatureUnit)\n");
            return MFD_ERROR;
        }
    }
    (* temperatureUnit_val_ptr_len_ptr ) = rowreq_ctx->data.temperatureUnit_len* sizeof(rowreq_ctx->data.temperatureUnit[0]);
    memcpy( (* temperatureUnit_val_ptr_ptr ), rowreq_ctx->data.temperatureUnit, rowreq_ctx->data.temperatureUnit_len* sizeof(rowreq_ctx->data.temperatureUnit[0]) );

    return MFD_SUCCESS;
} /* temperatureUnit_get */



/** @} */
