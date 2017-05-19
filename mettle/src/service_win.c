/**
 * @brief Service Management Functions
 * @file service_win.c
 */

#include "service.h"

int start_service(void)
{
	return 0;
}

static char *service_name = NULL;

void set_service_name(const char *name)
{
	char *tmp = strdump(name);
	char *base = strdup(basename(tmp));
	char *ext = strstr(base, ".exe");
	if (ext) {
		ext[0] = '\0';
	}
	service_name = base;
	free(tmp);
}
