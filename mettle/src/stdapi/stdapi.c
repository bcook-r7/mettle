/**
 * Copyright 2015 Rapid7
 * @brief Core API calls
 * @file stdapi.c
 */

#include "fs/file.c"
#include "net/config.c"
#include "sys/config.c"
#include "sys/process.c"

#define add_handler(name, cb) \
	tlv_dispatcher_add_handler(td, "stdapi_" name, cb, m)

void tlv_register_stdapi(struct mettle *m, struct tlv_dispatcher *td)
{
	add_handler("fs_chdir", fs_chdir);
	add_handler("fs_delete_file", fs_delete_file);
	add_handler("fs_expand_path", fs_expand_path);
	add_handler("fs_file_move", fs_file_move);
	add_handler("fs_getwd", fs_getwd);
	add_handler("fs_mkdir", fs_mkdir);
	add_handler("fs_ls", fs_ls);
	add_handler("fs_separator", fs_separator);
	add_handler("fs_stat", fs_stat);

	add_handler("net_config_get_interfaces", net_config_get_interfaces);
	add_handler("net_config_get_routes", net_config_get_routes);

	add_handler("sys_config_getenv", sys_config_getenv);
	add_handler("sys_config_getuid", sys_config_getuid);
	add_handler("sys_config_sysinfo", sys_config_sysinfo);

	// Process
	add_handler("sys_process_get_processes", sys_process_get_processes);
	add_handler("sys_process_attach", sys_process_attach);
	add_handler("sys_process_close", sys_process_close);
	add_handler("sys_process_execute", sys_process_execute);
	add_handler("sys_process_kill", sys_process_kill);
	add_handler("sys_process_get_processes", sys_process_get_processes);
	add_handler("sys_process_getpid", sys_process_getpid);
	add_handler("sys_process_get_info", sys_process_get_info);
	add_handler("sys_process_wait", sys_process_wait);
}
