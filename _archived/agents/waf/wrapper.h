#ifndef SENTINEL_MODSECURITY_WRAPPER_H
#define SENTINEL_MODSECURITY_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

// ModSecurity v3 headers
#ifdef MODSECURITY_VERSION_NUM
#if MODSECURITY_VERSION_NUM >= 030000
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <modsecurity/intervention.h>
#else
// ModSecurity v2 headers
#include <modsecurity.h>
#include <msc_api.h>
#include <msc_util.h>
#include <msc_release.h>
#endif
#else
// Default to v3
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <modsecurity/intervention.h>
#endif

// Helper structures for easier FFI
typedef struct {
    int status;
    int pause;
    char *url;
    char *log;
    int disruptive;
} ModSecurityIntervention;

// Wrapper functions for easier FFI usage
// These will be implemented in modsec_wrapper.c

// Initialize ModSecurity
void* modsec_init(void);

// Cleanup ModSecurity
void modsec_cleanup(void* modsec);

// Create a new rules set
void* modsec_create_rules_set(void);

// Add rules from file
int modsec_add_rules_file(void* rules_set, const char* file);

// Add rules from string
int modsec_add_rules(void* rules_set, const char* rules);

// Get number of rules
int modsec_get_rules_count(void* rules_set);

// Create a new transaction
void* modsec_new_transaction(void* modsec, void* rules_set, void* log_cb);

// Process connection
int modsec_process_connection(void* transaction, const char* client_ip, int client_port,
                              const char* server_ip, int server_port);

// Process URI
int modsec_process_uri(void* transaction, const char* uri, const char* protocol,
                       const char* http_version);

// Process request header
int modsec_process_request_headers(void* transaction);

// Add request header
int modsec_add_request_header(void* transaction, const char* key, const char* value);

// Process request body
int modsec_process_request_body(void* transaction);

// Append request body
int modsec_append_request_body(void* transaction, const unsigned char* body, size_t size);

// Process response headers
int modsec_process_response_headers(void* transaction, int status_code,
                                   const char* protocol);

// Add response header
int modsec_add_response_header(void* transaction, const char* key, const char* value);

// Process response body
int modsec_process_response_body(void* transaction);

// Append response body
int modsec_append_response_body(void* transaction, const unsigned char* body, size_t size);

// Check for intervention
int modsec_intervention(void* transaction, ModSecurityIntervention* intervention);

// Get transaction variable
const char* modsec_get_variable(void* transaction, const char* name);

// Get transaction ID
const char* modsec_get_transaction_id(void* transaction);

// Get rule messages
int modsec_get_rule_messages(void* transaction, char*** messages, int* count);

// Free rule messages
void modsec_free_rule_messages(char** messages, int count);

// Process logging
int modsec_process_logging(void* transaction);

// Cleanup transaction
void modsec_transaction_cleanup(void* transaction);

// Get ModSecurity version
const char* modsec_get_version(void);

// Set log callback function type
typedef void (*modsec_log_cb)(void* cb_data, int level, const char* message);

// Set server log callback
void modsec_set_log_callback(void* modsec, modsec_log_cb callback, void* cb_data);

// Log levels
#define MODSEC_LOG_DISABLE    0
#define MODSEC_LOG_ERROR      1
#define MODSEC_LOG_WARN       2
#define MODSEC_LOG_NOTICE     3
#define MODSEC_LOG_INFO       4
#define MODSEC_LOG_DEBUG      5
#define MODSEC_LOG_DEBUG2     6
#define MODSEC_LOG_DEBUG3     7
#define MODSEC_LOG_DEBUG4     8
#define MODSEC_LOG_DEBUG5     9

// Intervention actions
#define MODSEC_ACTION_ALLOW    0
#define MODSEC_ACTION_DENY     1
#define MODSEC_ACTION_DROP     2
#define MODSEC_ACTION_REDIRECT 3
#define MODSEC_ACTION_PROXY    4

// Phase definitions
#define MODSEC_PHASE_REQUEST_HEADERS  1
#define MODSEC_PHASE_REQUEST_BODY     2
#define MODSEC_PHASE_RESPONSE_HEADERS 3
#define MODSEC_PHASE_RESPONSE_BODY    4
#define MODSEC_PHASE_LOGGING          5

#ifdef __cplusplus
}
#endif

#endif // SENTINEL_MODSECURITY_WRAPPER_H