cmake_minimum_required(VERSION 3.7)

project(netsnmp)

set(snmplib_src
	snmplib/asn1.c
	snmplib/callback.c
	snmplib/check_varbind.c
	snmplib/container.c
	snmplib/container_binary_array.c
	snmplib/container_iterator.c
	snmplib/container_list_ssll.c
	snmplib/container_null.c
	snmplib/data_list.c
	snmplib/default_store.c
	snmplib/fd_event_manager.c	
	snmplib/inet_ntop.c
	snmplib/inet_pton.c
	snmplib/int64.c
	snmplib/keytools.c
	snmplib/large_fd_set.c
	snmplib/lcd_time.c
	snmplib/md5.c
	snmplib/mib.c
	snmplib/mt_support.c
	snmplib/oid_stash.c	
	snmplib/parse.c
	snmplib/read_config.c	
	snmplib/scapi.c
	snmplib/sd-daemon.c
	snmplib/snmp-tc.c
	snmplib/snmp.c
	snmplib/snmp_alarm.c
	snmplib/snmp_api.c
	snmplib/snmp_auth.c
	snmplib/snmp_client.c
	snmplib/snmp_debug.c
	snmplib/snmp_enum.c
	snmplib/snmp_logging.c
	snmplib/snmp_parse_args.c
	snmplib/snmp_secmod.c
	snmplib/snmp_service.c
	snmplib/snmp_transport.c
	snmplib/snmp_version.c
	snmplib/transports/snmpAliasDomain.c
	snmplib/transports/snmpCallbackDomain.c
	snmplib/transports/snmpIPBaseDomain.c
	snmplib/transports/snmpIPv4BaseDomain.c
	snmplib/transports/snmpIPv6BaseDomain.c
	snmplib/transports/snmpSocketBaseDomain.c
	snmplib/transports/snmpTCPBaseDomain.c
	snmplib/transports/snmpTCPDomain.c
	snmplib/transports/snmpTCPIPv6Domain.c
	snmplib/transports/snmpUDPBaseDomain.c
	snmplib/transports/snmpUDPDomain.c
	snmplib/transports/snmpUDPIPv4BaseDomain.c
	snmplib/transports/snmpUDPIPv6Domain.c
	snmplib/snmpusm.c
	snmplib/snmpv3.c	
	snmplib/system.c
	snmplib/tools.c
	snmplib/ucd_compat.c
	snmplib/vacm.c
	snmplib/strlcat.c
	snmplib/strlcpy.c	
)

if(WIN32)
	include_directories(win32)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
	list(APPEND snmplib_src
		snmplib/asprintf.c
		snmplib/opendir.c
		snmplib/readdir.c
		snmplib/closedir.c
		snmplib/getopt.c
		snmplib/gettimeofday.c
		snmplib/strtok_r.c
		snmplib/strtoull.c
		snmplib/winpipe.c
	)
else()
	list(APPEND snmplib_src
		snmplib/transports/snmpUnixDomain.c
	)
endif()

include_directories(include)
include_directories(agent)
include_directories(snmplib)


list(APPEND snmplib_src
	"snmplib/openssl/openssl_aes_cfb.c"
	"snmplib/openssl/openssl_aes_core.c"
	"snmplib/openssl/openssl_cbc_enc.c"
	"snmplib/openssl/openssl_cfb128.c"
	"snmplib/openssl/openssl_des_enc.c"
	"snmplib/openssl/openssl_md5.c"
	#"snmplib/openssl/openssl_ncbc_enc.c" #included in openssl_des_enc.c
	"snmplib/openssl/openssl_set_key.c"
	"snmplib/openssl/openssl_sha1.c"
)

add_library(netsnmplib ${snmplib_src})

add_executable(snmptrap "apps/snmptrap.c")
target_link_libraries(snmptrap netsnmplib)

set(snmptrapd_src 
	"apps/snmptrapd.c"
	"apps/snmptrapd_handlers.c"
	"apps/snmptrapd_auth.c"
	"apps/snmptrapd_log.c"
)

set(agent_src
	agent/agent_handler.c
	agent/agent_index.c
	agent/agent_read_config.c
	agent/agent_registry.c
	agent/agent_sysORTable.c
	agent/agent_trap.c
	agent/helpers/all_helpers.c
	agent/helpers/baby_steps.c
	agent/helpers/bulk_to_next.c
	agent/helpers/cache_handler.c
	agent/helpers/debug_handler.c
	agent/helpers/instance.c
	agent/helpers/mode_end_call.c
	agent/helpers/multiplexer.c
	agent/helpers/null.c
	agent/helpers/old_api.c
	agent/helpers/read_only.c
	agent/helpers/row_merge.c
	agent/helpers/scalar.c
	agent/helpers/scalar_group.c
	agent/helpers/serialize.c
	agent/snmp_agent.c
	agent/snmp_vars.c
	agent/helpers/snmp_get_statistic.c
	agent/helpers/stash_cache.c
	agent/helpers/stash_to_next.c
	agent/helpers/table.c
	agent/helpers/table_array.c
	agent/helpers/table_container.c
	agent/helpers/table_data.c
	agent/helpers/table_dataset.c
	agent/helpers/table_iterator.c
	agent/helpers/table_tdata.c
	agent/helpers/watcher.c
	agent/kernel.c
	agent/mibgroup/agent/nsVacmAccessTable.c
	agent/mibgroup/notification-log-mib/notification_log.c
	agent/mibgroup/agentx/subagent.c
	agent/mibgroup/agentx/agentx_config.c
	agent/mibgroup/agentx/client.c
	agent/mibgroup/agentx/protocol.c
	agent/mibgroup/agentx/master.c
	agent/mibgroup/agentx/master_admin.c
	agent/mibgroup/snmpv3/snmpEngine.c
	agent/mibgroup/snmpv3/usmUser.c
	agent/mibgroup/snmpv3/usmConf.c
	agent/mibgroup/mibII/vacm_conf.c
	agent/mibgroup/utilities/execute.c
	agent/mibgroup/utilities/iquery.c
	agent/mibgroup/util_funcs/header_generic.c
)
if(WIN32)
	list(APPEND snmptrapd_src snmplib/winservice.c)
else()
	list(APPEND agent_src agent/netsnmp_close_fds.c)
endif()

add_executable(snmptrapd ${snmptrapd_src})
add_library(agent ${agent_src})
target_link_libraries(snmptrapd agent netsnmplib)
target_include_directories(snmptrapd PRIVATE agent/mibgroup)
target_include_directories(agent PRIVATE agent/mibgroup)

add_executable(phosphor-snmp 
	"apps/phosphor_snmp.cpp" 
	"apps/snmp_notification.cpp" 
	#"apps/lg2_logger.cpp"
)
target_link_libraries(phosphor-snmp netsnmplib)
set_target_properties(phosphor-snmp PROPERTIES CXX_STANDARD 20)

if(WIN32)
	target_link_libraries(snmptrap ws2_32)
	target_link_libraries(snmptrapd ws2_32)
	target_link_libraries(phosphor-snmp ws2_32)
	target_compile_options(phosphor-snmp PRIVATE /Zc:__cplusplus)
endif()

target_compile_definitions(phosphor-snmp PRIVATE
    $<$<CONFIG:Debug>:
        NETSNMP_DEBUG=1
    >
)