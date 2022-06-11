/*
 * Note: this file originally auto-generated by mib2c
 * using mfd-top.m2c
 */
#ifndef JBODDEVDISKTABLE_H
#define JBODDEVDISKTABLE_H

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
config_require(INWIN-JBOD-MIB/jbodDevDiskTable/jbodDevDiskTable_interface)
config_require(INWIN-JBOD-MIB/jbodDevDiskTable/jbodDevDiskTable_data_access)
config_require(INWIN-JBOD-MIB/jbodDevDiskTable/jbodDevDiskTable_data_get)
config_require(INWIN-JBOD-MIB/jbodDevDiskTable/jbodDevDiskTable_data_set)
    /* *INDENT-ON*  */

/* OID and column number definitions for jbodDevDiskTable */
#include "jbodDevDiskTable_oids.h"

/* enum definions */
#include "jbodDevDiskTable_enums.h"

/* *********************************************************************
 * function declarations
 */
void init_jbodDevDiskTable(void);
void shutdown_jbodDevDiskTable(void);

/* *********************************************************************
 * Table declarations
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
/* *********************************************************************
 * When you register your mib, you get to provide a generic
 * pointer that will be passed back to you for most of the
 * functions calls.
 *
 * TODO:100:r: Review all context structures
 */
    /*
     * TODO:101:o: |-> Review jbodDevDiskTable registration context.
     */
typedef netsnmp_data_list jbodDevDiskTable_registration;

/**********************************************************************/
/*
 * TODO:110:r: |-> Review jbodDevDiskTable data context structure.
 * This structure is used to represent the data for jbodDevDiskTable.
 */
/*
 * This structure contains storage for all the columns defined in the
 * jbodDevDiskTable.
 */
typedef struct jbodDevDiskTable_data_s {
    
        /*
         * phyId(2)/INTEGER32/ASN_INTEGER/long(long)//l/A/w/e/R/d/h
         */
   long   phyId;
    
        /*
         * nlRate(3)/INTEGER32/ASN_INTEGER/long(long)//l/A/w/e/R/d/h
         */
   long   nlRate;
    
        /*
         * sasAddress(4)/OCTETSTR/ASN_OCTET_STR/char(char)//L/A/w/e/R/d/h
         */
   char   sasAddress[8];
size_t      sasAddress_len; /* # of char elements, not bytes */
    
        /*
         * diskType(5)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/w/e/R/d/H
         */
   char   diskType[128];
size_t      diskType_len; /* # of char elements, not bytes */
    
        /*
         * status(6)/SnmpAdminString/ASN_OCTET_STR/char(char)//L/A/w/e/R/d/H
         */
   char   status[128];
size_t      status_len; /* # of char elements, not bytes */
    
} jbodDevDiskTable_data;


/*
 * TODO:120:r: |-> Review jbodDevDiskTable mib index.
 * This structure is used to represent the index for jbodDevDiskTable.
 */
typedef struct jbodDevDiskTable_mib_index_s {

        /*
         * diskIndex(1)/INTEGER32/ASN_INTEGER/long(long)//l/a/w/e/R/d/h
         */
   long   diskIndex;


} jbodDevDiskTable_mib_index;

    /*
     * TODO:121:r: |   |-> Review jbodDevDiskTable max index length.
     * If you KNOW that your indexes will never exceed a certain
     * length, update this macro to that length.
*/
#define MAX_jbodDevDiskTable_IDX_LEN     1


/* *********************************************************************
 * TODO:130:o: |-> Review jbodDevDiskTable Row request (rowreq) context.
 * When your functions are called, you will be passed a
 * jbodDevDiskTable_rowreq_ctx pointer.
 */
typedef struct jbodDevDiskTable_rowreq_ctx_s {

    /** this must be first for container compare to work */
    netsnmp_index        oid_idx;
    oid                  oid_tmp[MAX_jbodDevDiskTable_IDX_LEN];
    
    jbodDevDiskTable_mib_index        tbl_idx;
    
    jbodDevDiskTable_data              data;

    /*
     * flags per row. Currently, the first (lower) 8 bits are reserved
     * for the user. See mfd.h for other flags.
     */
    u_int                       rowreq_flags;

    /*
     * TODO:131:o: |   |-> Add useful data to jbodDevDiskTable rowreq context.
     */
    
    /*
     * storage for future expansion
     */
    netsnmp_data_list             *jbodDevDiskTable_data_list;

} jbodDevDiskTable_rowreq_ctx;

typedef struct jbodDevDiskTable_ref_rowreq_ctx_s {
    jbodDevDiskTable_rowreq_ctx *rowreq_ctx;
} jbodDevDiskTable_ref_rowreq_ctx;

/* *********************************************************************
 * function prototypes
 */
    int jbodDevDiskTable_pre_request(jbodDevDiskTable_registration * user_context);
    int jbodDevDiskTable_post_request(jbodDevDiskTable_registration * user_context,
        int rc);

    int jbodDevDiskTable_rowreq_ctx_init(jbodDevDiskTable_rowreq_ctx *rowreq_ctx,
                                   void *user_init_ctx);
    void jbodDevDiskTable_rowreq_ctx_cleanup(jbodDevDiskTable_rowreq_ctx *rowreq_ctx);


    jbodDevDiskTable_rowreq_ctx *
                  jbodDevDiskTable_row_find_by_mib_index(jbodDevDiskTable_mib_index *mib_idx);

extern const oid jbodDevDiskTable_oid[];
extern const int jbodDevDiskTable_oid_size;


#include "jbodDevDiskTable_interface.h"
#include "jbodDevDiskTable_data_access.h"
#include "jbodDevDiskTable_data_get.h"
#include "jbodDevDiskTable_data_set.h"

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

#endif /* JBODDEVDISKTABLE_H */
/** @} */