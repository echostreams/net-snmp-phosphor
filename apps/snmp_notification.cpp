#include "snmp_notification.hpp"

//#include "snmp_util.hpp"
//#include "xyz/openbmc_project/Common/error.hpp"

//#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
/*
namespace lg2
{
    void error(const char* msg ...)
    {
        printf("error: %s\n", msg);
    }
    void debug(const char* msg ...)
    {
        printf("debug: %s\n", msg);
    }
}
*/
struct InternalFailure : public std::exception
{};

template <typename T, typename... Args>
[[noreturn]] void elog(Args... i_args)
{
    // Now throw an exception for this error
    throw T();
}

namespace phosphor
{
    namespace network
    {
        namespace snmp
        {

            //using namespace phosphor::logging;
            //using namespace sdbusplus::xyz::openbmc_project::Common::Error;

            using snmpSessionPtr =
                std::unique_ptr<netsnmp_session, decltype(&::snmp_close)>;

            oid SNMPTrapOID[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
            oid sysuptimeOID[] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };

            template <>
            u_char getASNType<uint32_t>()
            {
                return ASN_UNSIGNED;
            }

            template <>
            u_char getASNType<uint64_t>()
            {
                return ASN_OPAQUE_U64;
            }

            template <>
            u_char getASNType<int32_t>()
            {
                return ASN_INTEGER;
            }

            template <>
            u_char getASNType<std::string>()
            {
                return ASN_OCTET_STR;
            }

            bool Notification::addPDUVar(netsnmp_pdu& pdu, const OID& objID,
                size_t objIDLen, u_char type, Value val)
            {
                netsnmp_variable_list* varList = nullptr;
                switch (type)
                {
                case ASN_INTEGER:
                {
                    auto ltmp = std::get<int32_t>(val);
                    varList = snmp_pdu_add_variable(&pdu, objID.data(), objIDLen, type,
                        &ltmp, sizeof(ltmp));
                }
                break;
                case ASN_UNSIGNED:
                {
                    auto ltmp = std::get<uint32_t>(val);
                    varList = snmp_pdu_add_variable(&pdu, objID.data(), objIDLen, type,
                        &ltmp, sizeof(ltmp));
                }
                break;
                case ASN_OPAQUE_U64:
                {
                    auto ltmp = std::get<uint64_t>(val);
                    varList = snmp_pdu_add_variable(&pdu, objID.data(), objIDLen, type,
                        &ltmp, sizeof(ltmp));
                }
                break;
                case ASN_OCTET_STR:
                {
                    const auto& value = std::get<std::string>(val);
                    varList = snmp_pdu_add_variable(&pdu, objID.data(), objIDLen, type,
                        value.c_str(), value.length());
                }
                break;
                }
                return (varList == nullptr ? false : true);
            }

            void Notification::sendTrap()
            {
                constexpr auto comm = "public";
                netsnmp_session session{};
                snmp_sess_init(&session);

                init_snmp("snmpapp");

                // dump input/output packets in hexadecimal
                netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                    NETSNMP_DS_LIB_DUMP_PACKET, 1);

                // TODO: https://github.com/openbmc/openbmc/issues/3145
                session.version = SNMP_VERSION_2c;
                session.community = (u_char*)comm;
                session.community_len = strlen(comm);
                session.callback = nullptr;
                session.callback_magic = nullptr;

                //auto mgrs = getManagers();
                auto mgrs = { std::string("127.0.0.1") };

                for (auto& mgr : mgrs)
                {
                    session.peername = const_cast<char*>(mgr.c_str());
                    // create the session
                    auto ss = snmp_add(
                        &session,
                        netsnmp_transport_open_client("snmptrap", session.peername),
                        nullptr, nullptr);
                    if (!ss)
                    {
                        lg2::error("Unable to get the snmp session: {SNMPMANAGER}",
                            "SNMPMANAGER", mgr);
                        elog<InternalFailure>();
                    }

                    // Wrap the raw pointer in RAII
                    snmpSessionPtr sessionPtr(ss, &::snmp_close);

                    ss = nullptr;

                    auto pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
                    if (!pdu)
                    {
                        lg2::error("Failed to create notification PDU");
                        elog<InternalFailure>();
                    }

                    // https://tools.ietf.org/search/rfc3416#page-22
                    // add the sysUpTime.0 [RFC3418]
                    auto sysuptime = get_uptime();
                    std::string sysuptimeStr = std::to_string(sysuptime);

                    if (snmp_add_var(pdu, sysuptimeOID, sizeof(sysuptimeOID) / sizeof(oid),
                        't', sysuptimeStr.c_str()))

                    {
                        lg2::error("Failed to add the SNMP var(systime)");
                        snmp_free_pdu(pdu);
                        elog<InternalFailure>();
                    }

                    pdu->trap_type = SNMP_TRAP_ENTERPRISESPECIFIC;

                    auto trapInfo = getTrapOID();

                    // add the snmpTrapOID.0 [RFC3418]
                    if (!snmp_pdu_add_variable(pdu, SNMPTrapOID,
                        sizeof(SNMPTrapOID) / sizeof(oid),
                        ASN_OBJECT_ID, trapInfo.first.data(),
                        trapInfo.second * sizeof(oid)))
                    {
                        lg2::error("Failed to add the SNMP var(trapID)");
                        snmp_free_pdu(pdu);
                        elog<InternalFailure>();
                    }

                    auto objectList = getFieldOIDList();

                    for (const auto& object : objectList)
                    {
                        if (!addPDUVar(*pdu, std::get<0>(object), std::get<1>(object),
                            std::get<2>(object), std::get<3>(object)))
                        {
                            lg2::error("Failed to add the SNMP var");
                            snmp_free_pdu(pdu);
                            elog<InternalFailure>();
                        }
                    }
                    // pdu is freed by snmp_send
                    if (!snmp_send(sessionPtr.get(), pdu))
                    {
                        lg2::error("Failed to send the snmp trap.");
                        elog<InternalFailure>();
                    }                    

                    lg2::debug("Sent SNMP Trap: {MGR}", "MGR", mgr);
                }
            }

        } // namespace snmp
    } // namespace network
} // namespace phosphor