/*
 * Note: this file originally auto-generated by mib2c
 * using mfd-top.m2c
 */
#ifndef JBODDEVFANTABLE_H
#define JBODDEVFANTABLE_H

#ifdef __cplusplus
extern "C" {
#endif


/** @addtogroup misc misc: Miscellaneous routines
 *
 * @{
 */
#include <net-snmp/library/asn1.h>

/* other required module components */
    /* *INDENT-OFF*  */
config_add_mib(INWIN-JBOD-MIB)
config_require(INWIN-JBOD-MIB/jbodDevFanTable/jbodDevFanTable_interface)
config_require(INWIN-JBOD-MIB/jbodDevFanTable/jbodDevFanTable_data_access)
config_require(INWIN-JBOD-MIB/jbodDevFanTable/jbodDevFanTable_data_get)
config_require(INWIN-JBOD-MIB/jbodDevFanTable/jbodDevFanTable_data_set)
    /* *INDENT-ON*  */

/* OID and column number definitions for jbodDevFanTable */
#include "jbodDevFanTable_oids.h"

/* enum definions */
#include "jbodDevFanTable_enums.h"

/* *********************************************************************
 * function declarations
 */
void init_jbodDevFanTable(void);
void shutdown_jbodDevFanTable(void);

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
/* *********************************************************************
 * When you register your mib, you get to provide a generic
 * pointer that will be passed back to you for most of the
 * functions calls.
 *
 * TODO:100:r: Review all context structures
 */
    /*
     * TODO:101:o: |-> Review jbodDevFanTable registration context.
     */
typedef netsnmp_data_list jbodDevFanTable_registration;

/**********************************************************************/
/*
 * TODO:110:r: |-> Review jbodDevFanTable data context structure.
 * This structure is used to represent the data for jbodDevFanTable.
 */
/*
 * This structure contains storage for all the columns defined in the
 * jbodDevFanTable.
 */
typedef struct jbodDevFanTable_data_s {
    
        /*
         * fanDescription(2)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/w/e/R/d/H
         */
   char   fanDescription[128];
size_t      fanDescription_len; /* # of char elements, not bytes */
    
        /*
         * fanStatus(3)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/w/e/R/d/H
         */
   char   fanStatus[128];
size_t      fanStatus_len; /* # of char elements, not bytes */
    
        /*
         * fanValue(4)/INTEGER32/ASN_INTEGER/long(long)//l/A/w/e/r/d/h
         */
   long   fanValue;
    
        /*
         * fanUnit(5)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/w/e/R/d/H
         */
   char   fanUnit[128];
size_t      fanUnit_len; /* # of char elements, not bytes */
    
} jbodDevFanTable_data;


/*
 * TODO:120:r: |-> Review jbodDevFanTable mib index.
 * This structure is used to represent the index for jbodDevFanTable.
 */
typedef struct jbodDevFanTable_mib_index_s {

        /*
         * fanIndex(1)/INTEGER32/ASN_INTEGER/long(long)//l/a/w/e/R/d/h
         */
   long   fanIndex;


} jbodDevFanTable_mib_index;

    /*
     * TODO:121:r: |   |-> Review jbodDevFanTable max index length.
     * If you KNOW that your indexes will never exceed a certain
     * length, update this macro to that length.
*/
#define MAX_jbodDevFanTable_IDX_LEN     1


/* *********************************************************************
 * TODO:130:o: |-> Review jbodDevFanTable Row request (rowreq) context.
 * When your functions are called, you will be passed a
 * jbodDevFanTable_rowreq_ctx pointer.
 */
typedef struct jbodDevFanTable_rowreq_ctx_s {

    /** this must be first for container compare to work */
    netsnmp_index        oid_idx;
    oid                  oid_tmp[MAX_jbodDevFanTable_IDX_LEN];
    
    jbodDevFanTable_mib_index        tbl_idx;
    
    jbodDevFanTable_data              data;

    /*
     * flags per row. Currently, the first (lower) 8 bits are reserved
     * for the user. See mfd.h for other flags.
     */
    u_int                       rowreq_flags;

    /*
     * TODO:131:o: |   |-> Add useful data to jbodDevFanTable rowreq context.
     */
    
    /*
     * storage for future expansion
     */
    netsnmp_data_list             *jbodDevFanTable_data_list;

} jbodDevFanTable_rowreq_ctx;

typedef struct jbodDevFanTable_ref_rowreq_ctx_s {
    jbodDevFanTable_rowreq_ctx *rowreq_ctx;
} jbodDevFanTable_ref_rowreq_ctx;

/* *********************************************************************
 * function prototypes
 */
    int jbodDevFanTable_pre_request(jbodDevFanTable_registration * user_context);
    int jbodDevFanTable_post_request(jbodDevFanTable_registration * user_context,
        int rc);

    int jbodDevFanTable_rowreq_ctx_init(jbodDevFanTable_rowreq_ctx *rowreq_ctx,
                                   void *user_init_ctx);
    void jbodDevFanTable_rowreq_ctx_cleanup(jbodDevFanTable_rowreq_ctx *rowreq_ctx);


    jbodDevFanTable_rowreq_ctx *
                  jbodDevFanTable_row_find_by_mib_index(jbodDevFanTable_mib_index *mib_idx);

extern const oid jbodDevFanTable_oid[];
extern const int jbodDevFanTable_oid_size;


#include "jbodDevFanTable_interface.h"
#include "jbodDevFanTable_data_access.h"
#include "jbodDevFanTable_data_get.h"
#include "jbodDevFanTable_data_set.h"

/*
 * DUMMY markers, ignore
 *
 * TODO:099:x: *************************************************************
 * TODO:199:x: *************************************************************
 * TODO:299:x: *************************************************************
 * TODO:399:x: *************************************************************
 * TODO:499:x: *************************************************************
 */

#ifdef __cplusplus
}
#endif

#endif /* JBODDEVFANTABLE_H */
/** @} */