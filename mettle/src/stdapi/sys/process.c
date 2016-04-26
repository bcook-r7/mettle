/**
 * Copyright 2015 Rapid7
 * @brief System Process API
 * @file process.c
 */

#include <mettle.h>
#include <sigar.h>

#include "log.h"
#include "tlv.h"

struct process_data{
char* pname;
char* path;
char* user;
uint32_t arch;
uint32_t session;

};

/*
 * takes a sigar_pid_t in host byte order and returns it in network byte order
 * because sigar_pid_t can be 32 or 64-bit, regular htonl will not work
 *
 * to do: implement the pids in such a way that htonll works for all.
 */
sigar_pid_t hton_pid(sigar_pid_t pid)
{
	sigar_pid_t ret_pid=0;
	if (4==sizeof(pid))
	{
		ret_pid=htonl(pid);
	}
	else if (8==sizeof(pid))
	{
		ret_pid=((((uint64_t)htonl((uint64_t)pid)) << 32) + htonl(((uint64_t)pid) >> 32));
	}
	else
	{
		log_debug("unknown pid size");
	}

	return ret_pid;
}

/*
 * use sigar to create a process list and add the data to the response packet
 *
 * to do: build in the ability to query each process's architecture
 */

struct tlv_packet *sys_process_get_processes(struct tlv_handler_ctx *ctx)
{

	struct tlv_packet *ret_packet = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
    int status, i;
    uint32_t	proc_arch=PROCESS_ARCH_X86;
    sigar_t *sigar;
    sigar_t *proc_sigar;
    sigar_proc_list_t proclist;
    sigar_open(&sigar);

    status = sigar_proc_list_get(sigar, &proclist);

    if (status != SIGAR_OK)
    {
    	log_debug("proc_list error: %d (%s)\n",
               status, sigar_strerror(sigar, status));
    }
    else
    {
    	sigar_proc_cred_name_t	uname_data;
		sigar_pid_t		 		pid;
		sigar_pid_t 			net_pid;
		sigar_pid_t	 			net_ppid;
		sigar_proc_state_t 		pstate;
		sigar_proc_exe_t 		procexe;
    	struct tlv_packet *parent = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
    	struct tlv_packet *p;

		for (i=0; i<proclist.number; i++)
		{
			p = tlv_packet_new(TLV_TYPE_PROCESS_GROUP, 0);
			pid = proclist.data[i];

			status = sigar_proc_state_get(sigar, pid, &pstate);
			if (status != SIGAR_OK)
			{
				log_debug("error: %d (%s) proc_state(%d)\n",
					   status, sigar_strerror(sigar, status), pid);
			}
			else
			{

				net_pid=hton_pid(pid);
				net_ppid=hton_pid(pstate.ppid);

				p=tlv_packet_add_raw(p, TLV_TYPE_PID,
						&net_pid, sizeof(pid));
				p=tlv_packet_add_raw(p, TLV_TYPE_PARENT_PID,
						&net_ppid, sizeof(net_ppid));
				p=tlv_packet_add_raw(p, TLV_TYPE_PROCESS_ARCH,
						&proc_arch, sizeof(proc_arch));
				p=tlv_packet_add_raw(p, TLV_TYPE_PROCESS_NAME,
						pstate.name, strnlen(pstate.name, SIGAR_PROC_NAME_LEN)+1);

				/*
				 * the path data comes from another sigar struct; try to get it for each
				 * process and add the data if it is available to us
				 */
			    sigar_open(&proc_sigar);
				status = sigar_proc_exe_get(proc_sigar, pid, &procexe);

				if (status != SIGAR_OK)
				{
					p=tlv_packet_add_raw(p, TLV_TYPE_PROCESS_PATH, 	"PERMISSION DENIED", 18	);
				}
				else
				{
					p=tlv_packet_add_raw(p, TLV_TYPE_PROCESS_PATH, 	&procexe.name, 	1+strnlen(procexe.name, SIGAR_PATH_MAX+1));
				}


				/*
				 * the username data comes from another sigar struct; try to get it for each
				 * process and add the data if it is available to us
				 */
				status = sigar_proc_cred_name_get(sigar, pid, &uname_data);
				if (status != SIGAR_OK)
				{
					log_debug("error: %d (%s) proc_state(%d)\n", status, sigar_strerror(sigar, status), pid);
				}
				else
				{
					p=tlv_packet_add_raw(p, TLV_TYPE_USER_NAME, 	uname_data.user, 	1+strnlen(uname_data.user, SIGAR_CRED_NAME_MAX));
				}

				ret_packet=tlv_packet_add_child(parent, p);
			    sigar_close(proc_sigar);
			}
		}
	    sigar_proc_list_destroy(sigar, &proclist);

	    sigar_close(sigar);
    }

	return ret_packet;

}
/*
 * return a packet with a process handle if the OS is Windows-based
 * if the OS is not windows based, return ERROR_NOT_SUPPORTED
 * should be a wrapper for the open_process method in sigar
 */
struct tlv_packet *sys_process_attach(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *ret_packet = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	return ret_packet;

}

/*
 * close a process handle if the OS is Windows-based
 * and the pid provided is not the meterpreter pid
 * if the OS is not windows-based, (?)
 * No equivalent sigar method
 */
struct tlv_packet *sys_process_close(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *ret_packet = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	return ret_packet;

}

/*
 * Starts a process on any OS
 * Multiple configuration options, including pipes, ptys, create suspended, etc
 */
struct tlv_packet *sys_process_execute(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *ret_packet = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	return ret_packet;

}
/*
 * kills the process associated with the provided pid
 * should be a wrapper for sigar_proc_kill
 */
struct tlv_packet *sys_process_kill(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *ret_packet = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	return ret_packet;

}

/*
 * sends back a packet with the current [meterpreter] pid
 */
struct tlv_packet *sys_process_getpid(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *ret_packet = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	return ret_packet;

}

/*
 * in windows, returns a packet containing the name of the first loaded module
 * and the filename of the executable
 * can probably reproduce with sigar_proc_modules_get and sigar_proc_exe_peb_get
 */
struct tlv_packet *sys_process_get_info(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *ret_packet = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	return ret_packet;

}

/*
 * wrapper for windows WaitForSingleObject()
 * and 'nix waitpid()
 */
struct tlv_packet *sys_process_wait(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *ret_packet = tlv_packet_response_result(ctx, TLV_RESULT_FAILURE);
	return ret_packet;

}
