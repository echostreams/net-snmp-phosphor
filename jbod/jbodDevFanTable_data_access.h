/*
 * Note: this file originally auto-generated by mib2c
 * using mfd-data-access.m2c
 */
#ifndef JBODDEVFANTABLE_DATA_ACCESS_H
#define JBODDEVFANTABLE_DATA_ACCESS_H

#ifdef __cplusplus
extern "C" {
#endif


/* *********************************************************************
 * function declarations
 */

/* *********************************************************************
 * Table declarations
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


    int jbodDevFanTable_init_data(jbodDevFanTable_registration * jbodDevFanTable_reg);


void jbodDevFanTable_container_init(netsnmp_container **container_ptr_ptr);
void jbodDevFanTable_container_shutdown(netsnmp_container *container_ptr);

int jbodDevFanTable_container_load(netsnmp_container *container);
void jbodDevFanTable_container_free(netsnmp_container *container);

    /*
    ***************************************************
    ***             START EXAMPLE CODE              ***
    ***---------------------------------------------***/
/* *********************************************************************
 * Since we have no idea how you really access your data, we'll go with
 * a worst case example: a flat text file.
 */
#define MAX_LINE_SIZE 256
    /*
    ***---------------------------------------------***
    ***              END  EXAMPLE CODE              ***
    ***************************************************/
    int jbodDevFanTable_row_prep( jbodDevFanTable_rowreq_ctx *rowreq_ctx);



#ifdef __cplusplus
}
#endif

#endif /* JBODDEVFANTABLE_DATA_ACCESS_H */
