/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Anthony Minessale II <anthm@freeswitch.org>
 * Neal Horman <neal at wanlink dot com>
 *
 *
 * mod_alkcom.c -- Framework Demo Module
 *
 */
#include <switch.h>


#ifdef WIN32
#include <windows.h>
BOOL EnableShutdownPrivilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	// Open the process token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "ALKCOM: OpenProcessToken\n");
		return FALSE;
	}

	// Get the LUID for shutdown privilege
	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1; // one privilege to set
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Adjust the token privilege
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "ALKCOM: AdjustTokenPrivileges\n");
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}
#endif

static switch_bool_t reboot() {
#ifdef WIN32
	if (!EnableShutdownPrivilege()) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "ALKCOM: Failed to get shutdown privilege\n");
		return SWITCH_FALSE;
	}

	// Initiate reboot
	if (!ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_FLAG_PLANNED)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM: ExitWindowsEx\n");
		return SWITCH_TRUE;
	}
	return SWITCH_FALSE;
#else // WIN32
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "ALKCOM: WIN32 not declared!\n");
	return SWITCH_FALSE;
#endif // WIN32
}

/* Prototypes */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_alkcom_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_alkcom_runtime);
SWITCH_MODULE_LOAD_FUNCTION(mod_alkcom_load);

/* SWITCH_MODULE_DEFINITION(name, load, shutdown, runtime)
 * Defines a switch_loadable_module_function_table_t and a static const char[] modname
 */
SWITCH_MODULE_DEFINITION(mod_alkcom, mod_alkcom_load, mod_alkcom_shutdown, mod_alkcom_runtime);

typedef enum { 
	STATE_UNKNOWN = 0,
	STATE_PRIMARY = 1,
	STATE_SECONDARY = 2
} switchover_state_t;

static struct {
	char *floating_ip_addr;
	switchover_state_t state;
	switch_bool_t do_reboot;
	switch_bool_t is_running;
	switch_bool_t is_available;
} globals;


static switch_xml_config_string_options_t limit_config_ip = {NULL, 0,
	"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$"}; // ip address regex


static switch_xml_config_item_t instructions[] = {
	/*					parameter name        type                 reloadable   pointer						default value     options structure */
	SWITCH_CONFIG_ITEM("floating-ip", SWITCH_CONFIG_STRING, CONFIG_RELOADABLE, &globals.floating_ip_addr, "0.0.0.0",
					   &limit_config_ip,
					   "ip v4 address", "Specify floating ip address to check."),
	SWITCH_CONFIG_ITEM("reboot", SWITCH_CONFIG_BOOL, CONFIG_RELOADABLE, &globals.do_reboot, (void *)SWITCH_FALSE,
						NULL, "yes|no", "If enabled, print out sip messages on the console."),
	SWITCH_CONFIG_ITEM_END()
};

static switch_status_t do_config(switch_bool_t reload)
{
	memset(&globals, 0, sizeof(globals));
	globals.state = STATE_UNKNOWN;

	if (switch_xml_config_parse_module_settings("alkcom.conf", reload, instructions) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "ALKCOM: Could not open alkcom.conf\n");
		return SWITCH_STATUS_FALSE;
	}

	return SWITCH_STATUS_SUCCESS;
}

#define ALKCOM_API_USAGE "status/card_active[true|false]/reboot[true|false]"
SWITCH_STANDARD_API(alkcom_function)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM FUNCTION: ip - %s\n", globals.floating_ip_addr);
	int argc = 0;
	char *argv[2] = {0};
	char *mydata = NULL;
	char *value = NULL;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM FUNCTION: cmd - %s\n", cmd);

	if (!zstr(cmd)) {
		mydata = strdup(cmd);
		switch_assert(mydata);
		argc = switch_separate_string(mydata, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM FUNCTION: argc - '%d', argv0 - '%s',argv1 - '%s'\n", argc,
					  argv[0], argv[1]);

	if (argc < 1 || !argv[0]) { 
		goto usage; 
	}
	
	if (!strcasecmp(argv[0], "card_active")) {
		if (!strcasecmp(argv[1], "true")) {
			globals.is_available = SWITCH_TRUE;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM FUNCTION: card available set to true\n");
		} else if (!strcasecmp(argv[1], "false")) {
			globals.is_available = SWITCH_FALSE;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM FUNCTION: card available set to false\n");
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM FUNCTION: argv1 did not match\n");
			goto usage;
		}

	} else if (!strcasecmp(argv[0], "status")) {
		stream->write_function(stream, "+OK\nStatus: %d", globals.state);
		goto done;
	} else if (!strcasecmp(argv[0], "reboot")) {
		if (argc == 1) {
			stream->write_function(stream, "+OK\nReboot: %s", globals.do_reboot ? "yes" : "no");
			goto done;
		} else {
			if (!strcasecmp(argv[1], "true")) {
				globals.do_reboot = SWITCH_TRUE;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM FUNCTION: reboot set to true\n");
			} else if (!strcasecmp(argv[1], "false")) {
				globals.do_reboot = SWITCH_FALSE;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM FUNCTION: reboot set to false\n");
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM FUNCTION: argv1 did not match\n");
				goto usage;
			}
		}
	}
	else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM FUNCTION: argv0 did not match\n");
		goto usage;
	}
	
	stream->write_function(stream, "+OK\n");
	goto done;

usage:
	stream->write_function(stream, "-ERR Usage: alkcom %s\n", ALKCOM_API_USAGE);

done:

	switch_safe_free(mydata);

	return SWITCH_STATUS_SUCCESS;
}


/* Macro expands to: switch_status_t mod_alkcom_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool) */
SWITCH_MODULE_LOAD_FUNCTION(mod_alkcom_load)
{
	switch_api_interface_t *api_interface;
	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Hello World!\n");

	do_config(SWITCH_FALSE);

	SWITCH_ADD_API(api_interface, "alkcom", "alkcom API", alkcom_function, "alckom acitve=1|0|true|false");
	switch_console_set_complete("add alkcom card_active true");
	switch_console_set_complete("add alkcom card_active false");
	switch_console_set_complete("add alkcom status");
	switch_console_set_complete("add alkcom reboot");
	switch_console_set_complete("add alkcom reboot true");
	switch_console_set_complete("add alkcom reboot false");


	globals.is_running = SWITCH_TRUE;

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

/*
  Called when the system shuts down
  Macro expands to: switch_status_t mod_alkcom_shutdown() */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_alkcom_shutdown)
{
	/* Cleanup dynamically allocated config settings */
	globals.is_running = SWITCH_FALSE;
	switch_xml_config_cleanup(instructions);
	return SWITCH_STATUS_SUCCESS;
}

static switch_bool_t is_network_card_available() {
	return globals.is_available; 
}

static void start_connections() {
	// reload mod sofia -> sofia recover
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM: Sofia should start here\n");
	
	switch_stream_handle_t stream = {0};

	SWITCH_STANDARD_STREAM(stream);

	switch_api_execute("reload", "mod_sofia", NULL, &stream);
	switch_api_execute("sofia", "recover", NULL, &stream);

	switch_safe_free(stream.data);
}

static void restart_workstation() {
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
					  "ALKCOM: restart should happend here\n");
	if (reboot()) 
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM: restart happening\n");
	} else 
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM: could not restart workstation\n");
		// kill switch ???
		// kill sofia ???
		// restart FS ???
	};
}

static void check_switchover_state()
{
	//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM FUNCTION: is card available - %d\n", globals.is_available);
	switch (globals.state) {
		case STATE_UNKNOWN: {
			if (is_network_card_available()) { 
				globals.state = STATE_PRIMARY;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM: State changed from STATE_UNKNOWN to STATE_PRIMARY\n");
				start_connections();
			} else {
				globals.state = STATE_SECONDARY;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
								  "ALKCOM: State changed from STATE_UNKNOWN to STATE_SECONDARY\n");
			}
			break;
		}
		case STATE_PRIMARY: {
			if (is_network_card_available()) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
								  "ALKCOM: State stays STATE_PRIMARY\n");
			} else {
				globals.state = STATE_SECONDARY;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
								  "ALKCOM: State changed from STATE_PRIMARY to STATE_SECONDARY\n");
				
				if (globals.do_reboot) {
					restart_workstation(); 
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
									  "ALKCOM: Reboot is set to false\n");
				}
			}
			break;
		}
		case STATE_SECONDARY: {
			if (is_network_card_available()) {
				globals.state = STATE_PRIMARY;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
								  "ALKCOM: State changed from STATE_SECONDARY to STATE_PRIMARY\n");
				start_connections();
				
			} else {
				globals.state = STATE_SECONDARY;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ALKCOM: State stays STATE_SECONDARY\n");
			}
			break;
		}
		default: {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ALKCOM: Unkown Value of state: %d\n", globals.state);
			break;
		}
	}
}

//  If it exists, this is called in it's own thread when the module-load completes
//  If it returns anything but SWITCH_STATUS_TERM it will be called again automatically
//  Macro expands to: switch_status_t mod_alkcom_runtime()
SWITCH_MODULE_RUNTIME_FUNCTION(mod_alkcom_runtime)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "ALKCOM: Entered runtime\n");

	while (globals.is_running)
	{
		switch_sleep(5 * 1000000);
		//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Hello World from alkcom runtime\n");
		check_switchover_state();
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "ALKCOM: Exit runtime\n");
	//return SWITCH_STATUS_TERM;
	return SWITCH_STATUS_TERM;
}


/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet
 */
