/*
 * Note: this file originally auto-generated by mib2c
 * using mfd-data-access.m2c
 */
#ifndef JBODDEVTEMPERATURETABLE_DATA_ACCESS_H
#define JBODDEVTEMPERATURETABLE_DATA_ACCESS_H

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
 *** Table jbodDevTemperatureTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * INWIN-JBOD-MIB::jbodDevTemperatureTable is subid 2 of product.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.47464.1.2.2, length: 10
*/


    int jbodDevTemperatureTable_init_data(jbodDevTemperatureTable_registration * jbodDevTemperatureTable_reg);


void jbodDevTemperatureTable_container_init(netsnmp_container **container_ptr_ptr);
void jbodDevTemperatureTable_container_shutdown(netsnmp_container *container_ptr);

int jbodDevTemperatureTable_container_load(netsnmp_container *container);
void jbodDevTemperatureTable_container_free(netsnmp_container *container);

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
    int jbodDevTemperatureTable_row_prep( jbodDevTemperatureTable_rowreq_ctx *rowreq_ctx);



#ifdef __cplusplus
}
#endif

#endif /* JBODDEVTEMPERATURETABLE_DATA_ACCESS_H */
