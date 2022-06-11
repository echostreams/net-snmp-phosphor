/*
 * Note: this file originally auto-generated by mib2c
 * using mfd-data-get.m2c
 *
 * @file jbodDevDiskTable_data_get.h
 *
 * @addtogroup get
 *
 * Prototypes for get functions
 *
 * @{
 */
#ifndef JBODDEVDISKTABLE_DATA_GET_H
#define JBODDEVDISKTABLE_DATA_GET_H

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
 *** Table jbodDevDiskTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * INWIN-JBOD-MIB::jbodDevDiskTable is subid 5 of product.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.47464.1.2.5, length: 10
*/
    /*
     * indexes
     */

    int phyId_get( jbodDevDiskTable_rowreq_ctx *rowreq_ctx, long * phyId_val_ptr );
    int nlRate_get( jbodDevDiskTable_rowreq_ctx *rowreq_ctx, long * nlRate_val_ptr );
    int sasAddress_get( jbodDevDiskTable_rowreq_ctx *rowreq_ctx, char **sasAddress_val_ptr_ptr, size_t *sasAddress_val_ptr_len_ptr );
    int diskType_get( jbodDevDiskTable_rowreq_ctx *rowreq_ctx, char **diskType_val_ptr_ptr, size_t *diskType_val_ptr_len_ptr );
    int status_get( jbodDevDiskTable_rowreq_ctx *rowreq_ctx, char **status_val_ptr_ptr, size_t *status_val_ptr_len_ptr );


int jbodDevDiskTable_indexes_set_tbl_idx(jbodDevDiskTable_mib_index *tbl_idx, long diskIndex_val);
int jbodDevDiskTable_indexes_set(jbodDevDiskTable_rowreq_ctx *rowreq_ctx, long diskIndex_val);




#ifdef __cplusplus
}
#endif

#endif /* JBODDEVDISKTABLE_DATA_GET_H */
/** @} */