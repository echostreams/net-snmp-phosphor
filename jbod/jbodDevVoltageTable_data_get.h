/*
 * Note: this file originally auto-generated by mib2c
 * using mfd-data-get.m2c
 *
 * @file jbodDevVoltageTable_data_get.h
 *
 * @addtogroup get
 *
 * Prototypes for get functions
 *
 * @{
 */
#ifndef JBODDEVVOLTAGETABLE_DATA_GET_H
#define JBODDEVVOLTAGETABLE_DATA_GET_H

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
 *** Table jbodDevVoltageTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * INWIN-JBOD-MIB::jbodDevVoltageTable is subid 3 of product.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.47464.1.2.3, length: 10
*/
    /*
     * indexes
     */

    int voltageDescription_get( jbodDevVoltageTable_rowreq_ctx *rowreq_ctx, char **voltageDescription_val_ptr_ptr, size_t *voltageDescription_val_ptr_len_ptr );
    int voltageStatus_get( jbodDevVoltageTable_rowreq_ctx *rowreq_ctx, char **voltageStatus_val_ptr_ptr, size_t *voltageStatus_val_ptr_len_ptr );
    int voltageValue_get( jbodDevVoltageTable_rowreq_ctx *rowreq_ctx, long * voltageValue_val_ptr );
    int voltageUnit_get( jbodDevVoltageTable_rowreq_ctx *rowreq_ctx, char **voltageUnit_val_ptr_ptr, size_t *voltageUnit_val_ptr_len_ptr );


int jbodDevVoltageTable_indexes_set_tbl_idx(jbodDevVoltageTable_mib_index *tbl_idx, long voltageIndex_val);
int jbodDevVoltageTable_indexes_set(jbodDevVoltageTable_rowreq_ctx *rowreq_ctx, long voltageIndex_val);




#ifdef __cplusplus
}
#endif

#endif /* JBODDEVVOLTAGETABLE_DATA_GET_H */
/** @} */