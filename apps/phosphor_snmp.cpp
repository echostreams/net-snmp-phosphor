// net-snmp requires a very specific header include order.
// disable clang-format around this block
// clang-format off
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
// clang-format on

#include "snmp.hpp"
#include "snmp_notification.hpp"

using namespace phosphor::network::snmp;

int main(int argc, char** argv)
{
    SOCK_STARTUP;

    try
    {
        uint32_t errorID = 111;
        uint64_t timestamp = 0x12345678;
        int32_t isev = 7;        

        sendTrap<OBMCErrorNotification>(errorID, timestamp, isev, "Test V2 Message.");

        sendTrapV3<OBMCErrorNotification>(errorID, timestamp, isev, "Test V3 Message.");

    }
    //catch (const InternalFailure& e)
    catch (const std::exception& e)
    {
        /*
        log<level::INFO>(
            "Failed to send SNMP trap",
            phosphor::logging::entry("ERROR_ID=%d", errorID),
            phosphor::logging::entry("TIMESTAMP=%llu", timestamp),
            phosphor::logging::entry("SEVERITY=%s",
                convertForMessage(sev).c_str()),
            phosphor::logging::entry("MESSAGE=%s", message.c_str()));
        */
        printf("std::exception: %s\n", e.what());
    }

    SOCK_CLEANUP;
	return 0;
}