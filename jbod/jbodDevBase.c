/*
 * Note: this file originally auto-generated by mib2c
 * using mib2c.scalar.conf
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "jbodDevBase.h"

/** Initializes the jbodDevBase module */
char jbodDevSerial[128] = "1634N5D707";
char jbodDevSwVersion[128] = "2.0.12";
char jbodDevMacAddress[128] = { 0xac, 0x40, 0xea, 0x01, 0x0b, 0xd0 };
char jbodDevDateTime[128] = { 2022/256, 2022%256, 06, 10, 11, 48, 30, 00, '+', 0, 0};// "2022-06-10 11:48:30";
char jbodDevExpanderPHwVersion[128] = "1.2.3.4";
char jbodDevExpanderSHwVersion[128] = "1.2.3.4";
char jbodDevExpanderPFwVersion[128] = "1.2.3.4";
char jbodDevExpanderSFwVersion[128] = "1.2.3.4";
char jbodDevExpanderPMfgVersion[128] = "1.2.3.4";
char jbodDevExpanderSMfgVersion[128] = "1.2.3.4";
char jbodDevSwUpgradeName[64] = "fw.bin";
char jbodDevSwUpgradeServer[] = { 192, 168, 100, 134 };
int jbodDevSwUpgrade = 0;
int jbodDevResetNow = 0;

void
init_jbodDevBase(void)
{
    const oid jbodDevSerial_oid[] = { 1,3,6,1,4,1,47464,1,2,1,1 };
    const oid jbodDevSwVersion_oid[] = { 1,3,6,1,4,1,47464,1,2,1,2 };
    const oid jbodDevMacAddress_oid[] = { 1,3,6,1,4,1,47464,1,2,1,3 };
    const oid jbodDevDateTime_oid[] = { 1,3,6,1,4,1,47464,1,2,1,4 };
    const oid jbodDevExpanderPHwVersion_oid[] = { 1,3,6,1,4,1,47464,1,2,1,5 };
    const oid jbodDevExpanderSHwVersion_oid[] = { 1,3,6,1,4,1,47464,1,2,1,6 };
    const oid jbodDevExpanderPFwVersion_oid[] = { 1,3,6,1,4,1,47464,1,2,1,7 };
    const oid jbodDevExpanderSFwVersion_oid[] = { 1,3,6,1,4,1,47464,1,2,1,8 };
    const oid jbodDevExpanderPMfgVersion_oid[] = { 1,3,6,1,4,1,47464,1,2,1,9 };
    const oid jbodDevExpanderSMfgVersion_oid[] = { 1,3,6,1,4,1,47464,1,2,1,10 };
    const oid jbodDevSwUpgradeName_oid[] = { 1,3,6,1,4,1,47464,1,2,1,11 };
    const oid jbodDevSwUpgradeServer_oid[] = { 1,3,6,1,4,1,47464,1,2,1,12 };
    const oid jbodDevSwUpgrade_oid[] = { 1,3,6,1,4,1,47464,1,2,1,13 };
    const oid jbodDevResetNow_oid[] = { 1,3,6,1,4,1,47464,1,2,1,14 };

  DEBUGMSGTL(("jbodDevBase", "Initializing\n"));
  /*
  {
#define SYS_STRING_LEN	256
      static char     version_descr[SYS_STRING_LEN] = "Quantum QTM-FUSN-212J Storage System-HW:1.0 SW:2.0.12";
      const oid sysDescr_oid[] = { 1, 3, 6, 1, 2, 1, 1, 1 };
      static netsnmp_watcher_info sysDescr_winfo;
      netsnmp_register_watched_scalar(
          netsnmp_create_handler_registration(
              "mibII/sysDescr", NULL, sysDescr_oid, OID_LENGTH(sysDescr_oid),
              HANDLER_CAN_RONLY),
          netsnmp_init_watcher_info(&sysDescr_winfo, version_descr, 0,
              ASN_OCTET_STR, WATCHER_SIZE_STRLEN));
  }
  */
  init_system_mib();
  init_sysORTable();
  extern int      register_sysORTable(oid*, size_t, const char*);
  extern int      unregister_sysORTable(oid*, size_t);
  static oid      sysORTable_reg[] = { 0, 0 };
  static size_t   sysORTable_reglen = 2;
  register_sysORTable(sysORTable_reg, sysORTable_reglen, "JBOD Storage System");

    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevSerial", handle_jbodDevSerial,
                               jbodDevSerial_oid, OID_LENGTH(jbodDevSerial_oid),
                               HANDLER_CAN_RONLY
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevSwVersion", handle_jbodDevSwVersion,
                               jbodDevSwVersion_oid, OID_LENGTH(jbodDevSwVersion_oid),
                               HANDLER_CAN_RONLY
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevMacAddress", handle_jbodDevMacAddress,
                               jbodDevMacAddress_oid, OID_LENGTH(jbodDevMacAddress_oid),
                               HANDLER_CAN_RONLY
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevDateTime", handle_jbodDevDateTime,
                               jbodDevDateTime_oid, OID_LENGTH(jbodDevDateTime_oid),
                               HANDLER_CAN_RWRITE
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevExpanderPHwVersion", handle_jbodDevExpanderPHwVersion,
                               jbodDevExpanderPHwVersion_oid, OID_LENGTH(jbodDevExpanderPHwVersion_oid),
                               HANDLER_CAN_RONLY
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevExpanderSHwVersion", handle_jbodDevExpanderSHwVersion,
                               jbodDevExpanderSHwVersion_oid, OID_LENGTH(jbodDevExpanderSHwVersion_oid),
                               HANDLER_CAN_RONLY
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevExpanderPFwVersion", handle_jbodDevExpanderPFwVersion,
                               jbodDevExpanderPFwVersion_oid, OID_LENGTH(jbodDevExpanderPFwVersion_oid),
                               HANDLER_CAN_RONLY
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevExpanderSFwVersion", handle_jbodDevExpanderSFwVersion,
                               jbodDevExpanderSFwVersion_oid, OID_LENGTH(jbodDevExpanderSFwVersion_oid),
                               HANDLER_CAN_RONLY
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevExpanderPMfgVersion", handle_jbodDevExpanderPMfgVersion,
                               jbodDevExpanderPMfgVersion_oid, OID_LENGTH(jbodDevExpanderPMfgVersion_oid),
                               HANDLER_CAN_RONLY
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevExpanderSMfgVersion", handle_jbodDevExpanderSMfgVersion,
                               jbodDevExpanderSMfgVersion_oid, OID_LENGTH(jbodDevExpanderSMfgVersion_oid),
                               HANDLER_CAN_RONLY
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevSwUpgradeName", handle_jbodDevSwUpgradeName,
                               jbodDevSwUpgradeName_oid, OID_LENGTH(jbodDevSwUpgradeName_oid),
                               HANDLER_CAN_RWRITE
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevSwUpgradeServer", handle_jbodDevSwUpgradeServer,
                               jbodDevSwUpgradeServer_oid, OID_LENGTH(jbodDevSwUpgradeServer_oid),
                               HANDLER_CAN_RWRITE
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevSwUpgrade", handle_jbodDevSwUpgrade,
                               jbodDevSwUpgrade_oid, OID_LENGTH(jbodDevSwUpgrade_oid),
                               HANDLER_CAN_RWRITE
        ));
    netsnmp_register_scalar(
        netsnmp_create_handler_registration("jbodDevResetNow", handle_jbodDevResetNow,
                               jbodDevResetNow_oid, OID_LENGTH(jbodDevResetNow_oid),
                               HANDLER_CAN_RWRITE
        ));
}

int
handle_jbodDevSerial(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                     jbodDevSerial/* XXX: a pointer to the scalar's data */,
                                     strlen(jbodDevSerial)/* XXX: the length of the data in bytes */);
            break;


        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevSerial\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevSwVersion(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                     jbodDevSwVersion/* XXX: a pointer to the scalar's data */,
                                     strlen(jbodDevSwVersion)/* XXX: the length of the data in bytes */);
            break;


        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevSwVersion\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevMacAddress(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                jbodDevMacAddress/* XXX: a pointer to the scalar's data */,
                6/* XXX: the length of the data in bytes */);
            break;


        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevMacAddress\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevDateTime(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    int ret;
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                     jbodDevDateTime/* XXX: a pointer to the scalar's data */,
                                     11/* XXX: the length of the data in bytes */);
            break;

        /*
         * SET REQUEST
         *
         * multiple states in the transaction.  See:
         * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
        case MODE_SET_RESERVE1:
                /* or you could use netsnmp_check_vb_type_and_size instead */
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_OCTET_STR);
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;

        case MODE_SET_RESERVE2:
            /* XXX malloc "undo" storage buffer */
            if (1/* XXX if malloc, or whatever, failed: */) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
            }
            break;

        case MODE_SET_FREE:
            /* XXX: free resources allocated in RESERVE1 and/or
               RESERVE2.  Something failed somewhere, and the states
               below won't be called. */
            break;

        case MODE_SET_ACTION:
            /* XXX: perform the value change here */
            if (1/* XXX: error? */) {
                netsnmp_set_request_error(reqinfo, requests, 0/* some error */);
            }
            break;

        case MODE_SET_COMMIT:
            /* XXX: delete temporary storage */
            if (1/* XXX: error? */) {
                /* try _really_really_ hard to never get to this point */
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_COMMITFAILED);
            }
            break;

        case MODE_SET_UNDO:
            /* XXX: UNDO and return to previous value for the object */
            if (1/* XXX: error? */) {
                /* try _really_really_ hard to never get to this point */
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_UNDOFAILED);
            }
            break;

        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevDateTime\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevExpanderPHwVersion(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                     jbodDevExpanderPHwVersion/* XXX: a pointer to the scalar's data */,
                                     strlen(jbodDevExpanderPHwVersion)/* XXX: the length of the data in bytes */);
            break;


        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevExpanderPHwVersion\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevExpanderSHwVersion(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                jbodDevExpanderSHwVersion/* XXX: a pointer to the scalar's data */,
                strlen(jbodDevExpanderSHwVersion)/* XXX: the length of the data in bytes */);
            break;


        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevExpanderSHwVersion\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevExpanderPFwVersion(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                jbodDevExpanderPFwVersion/* XXX: a pointer to the scalar's data */,
                strlen(jbodDevExpanderPFwVersion)/* XXX: the length of the data in bytes */);
            break;


        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevExpanderPFwVersion\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevExpanderSFwVersion(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                jbodDevExpanderSFwVersion/* XXX: a pointer to the scalar's data */,
                strlen(jbodDevExpanderSFwVersion)/* XXX: the length of the data in bytes */);
            break;


        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevExpanderSFwVersion\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevExpanderPMfgVersion(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                jbodDevExpanderPMfgVersion/* XXX: a pointer to the scalar's data */,
                strlen(jbodDevExpanderPMfgVersion)/* XXX: the length of the data in bytes */);
            break;


        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevExpanderPMfgVersion\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevExpanderSMfgVersion(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                jbodDevExpanderSMfgVersion/* XXX: a pointer to the scalar's data */,
                strlen(jbodDevExpanderSMfgVersion)/* XXX: the length of the data in bytes */);
            break;


        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevExpanderSMfgVersion\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevSwUpgradeName(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    int ret;
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                jbodDevSwUpgradeName/* XXX: a pointer to the scalar's data */,
                strlen(jbodDevSwUpgradeName)/* XXX: the length of the data in bytes */);
            break;

        /*
         * SET REQUEST
         *
         * multiple states in the transaction.  See:
         * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
        case MODE_SET_RESERVE1:
                /* or you could use netsnmp_check_vb_type_and_size instead */
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_OCTET_STR);
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;

        case MODE_SET_RESERVE2:
            /* XXX malloc "undo" storage buffer */
            if (1/* XXX if malloc, or whatever, failed: */) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
            }
            break;

        case MODE_SET_FREE:
            /* XXX: free resources allocated in RESERVE1 and/or
               RESERVE2.  Something failed somewhere, and the states
               below won't be called. */
            break;

        case MODE_SET_ACTION:
            /* XXX: perform the value change here */
            if (1/* XXX: error? */) {
                netsnmp_set_request_error(reqinfo, requests, 0/* some error */);
            }
            break;

        case MODE_SET_COMMIT:
            /* XXX: delete temporary storage */
            if (1/* XXX: error? */) {
                /* try _really_really_ hard to never get to this point */
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_COMMITFAILED);
            }
            break;

        case MODE_SET_UNDO:
            /* XXX: UNDO and return to previous value for the object */
            if (1/* XXX: error? */) {
                /* try _really_really_ hard to never get to this point */
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_UNDOFAILED);
            }
            break;

        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevSwUpgradeName\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevSwUpgradeServer(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    int ret;
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_IPADDRESS,
                jbodDevSwUpgradeServer/* XXX: a pointer to the scalar's data */,
                sizeof(jbodDevSwUpgradeServer)/* XXX: the length of the data in bytes */);
            break;

        /*
         * SET REQUEST
         *
         * multiple states in the transaction.  See:
         * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
        case MODE_SET_RESERVE1:
                /* or you could use netsnmp_check_vb_type_and_size instead */
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_IPADDRESS);
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;

        case MODE_SET_RESERVE2:
            /* XXX malloc "undo" storage buffer */
            if (1/* XXX if malloc, or whatever, failed: */) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
            }
            break;

        case MODE_SET_FREE:
            /* XXX: free resources allocated in RESERVE1 and/or
               RESERVE2.  Something failed somewhere, and the states
               below won't be called. */
            break;

        case MODE_SET_ACTION:
            /* XXX: perform the value change here */
            if (1/* XXX: error? */) {
                netsnmp_set_request_error(reqinfo, requests, 0/* some error */);
            }
            break;

        case MODE_SET_COMMIT:
            /* XXX: delete temporary storage */
            if (1/* XXX: error? */) {
                /* try _really_really_ hard to never get to this point */
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_COMMITFAILED);
            }
            break;

        case MODE_SET_UNDO:
            /* XXX: UNDO and return to previous value for the object */
            if (1/* XXX: error? */) {
                /* try _really_really_ hard to never get to this point */
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_UNDOFAILED);
            }
            break;

        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevSwUpgradeServer\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevSwUpgrade(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    int ret;
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER,
                &jbodDevSwUpgrade/* XXX: a pointer to the scalar's data */,
                4/* XXX: the length of the data in bytes */);
            break;

        /*
         * SET REQUEST
         *
         * multiple states in the transaction.  See:
         * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
        case MODE_SET_RESERVE1:
                /* or you could use netsnmp_check_vb_type_and_size instead */
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;

        case MODE_SET_RESERVE2:
            /* XXX malloc "undo" storage buffer */
            if (1/* XXX if malloc, or whatever, failed: */) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
            }
            break;

        case MODE_SET_FREE:
            /* XXX: free resources allocated in RESERVE1 and/or
               RESERVE2.  Something failed somewhere, and the states
               below won't be called. */
            break;

        case MODE_SET_ACTION:
            /* XXX: perform the value change here */
            if (1/* XXX: error? */) {
                netsnmp_set_request_error(reqinfo, requests, 0/* some error */);
            }
            break;

        case MODE_SET_COMMIT:
            /* XXX: delete temporary storage */
            if (1/* XXX: error? */) {
                /* try _really_really_ hard to never get to this point */
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_COMMITFAILED);
            }
            break;

        case MODE_SET_UNDO:
            /* XXX: UNDO and return to previous value for the object */
            if (1/* XXX: error? */) {
                /* try _really_really_ hard to never get to this point */
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_UNDOFAILED);
            }
            break;

        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevSwUpgrade\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}
int
handle_jbodDevResetNow(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    int ret;
    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER,
                                     &jbodDevResetNow/* XXX: a pointer to the scalar's data */,
                                     4/* XXX: the length of the data in bytes */);
            break;

        /*
         * SET REQUEST
         *
         * multiple states in the transaction.  See:
         * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
        case MODE_SET_RESERVE1:
                /* or you could use netsnmp_check_vb_type_and_size instead */
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;

        case MODE_SET_RESERVE2:
            /* XXX malloc "undo" storage buffer */
            if (1/* XXX if malloc, or whatever, failed: */) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
            }
            break;

        case MODE_SET_FREE:
            /* XXX: free resources allocated in RESERVE1 and/or
               RESERVE2.  Something failed somewhere, and the states
               below won't be called. */
            break;

        case MODE_SET_ACTION:
            /* XXX: perform the value change here */
            if (1/* XXX: error? */) {
                netsnmp_set_request_error(reqinfo, requests, 0/* some error */);
            }
            break;

        case MODE_SET_COMMIT:
            /* XXX: delete temporary storage */
            if (1/* XXX: error? */) {
                /* try _really_really_ hard to never get to this point */
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_COMMITFAILED);
            }
            break;

        case MODE_SET_UNDO:
            /* XXX: UNDO and return to previous value for the object */
            if (1/* XXX: error? */) {
                /* try _really_really_ hard to never get to this point */
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_UNDOFAILED);
            }
            break;

        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_jbodDevResetNow\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}