/*
 * Note: this file originally auto-generated by mib2c
 * using mfd-data-get.m2c
 *
 * @file jbodDevLogTable_data_get.h
 *
 * @addtogroup get
 *
 * Prototypes for get functions
 *
 * @{
 */
#ifndef JBODDEVLOGTABLE_DATA_GET_H
#define JBODDEVLOGTABLE_DATA_GET_H

#ifdef __cplusplus
extern "C" {
#endif

/* *********************************************************************
 * GET function declarations
 */

/* *********************************************************************
 * GET Table declarations
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table jbodDevLogTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * INWIN-JBOD-MIB::jbodDevLogTable is subid 6 of product.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.47464.1.2.6, length: 10
*/
    /*
     * indexes
     */

    int logTime_get( jbodDevLogTable_rowreq_ctx *rowreq_ctx, char **logTime_val_ptr_ptr, size_t *logTime_val_ptr_len_ptr );
    int logType_get( jbodDevLogTable_rowreq_ctx *rowreq_ctx, char **logType_val_ptr_ptr, size_t *logType_val_ptr_len_ptr );
    int logDescription_get( jbodDevLogTable_rowreq_ctx *rowreq_ctx, char **logDescription_val_ptr_ptr, size_t *logDescription_val_ptr_len_ptr );


int jbodDevLogTable_indexes_set_tbl_idx(jbodDevLogTable_mib_index *tbl_idx, long logIndex_val);
int jbodDevLogTable_indexes_set(jbodDevLogTable_rowreq_ctx *rowreq_ctx, long logIndex_val);




#ifdef __cplusplus
}
#endif

#endif /* JBODDEVLOGTABLE_DATA_GET_H */
/** @} */
