#include "../wrapper.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ModSecurity v3 implementation
#if defined(MODSECURITY_VERSION_NUM) && MODSECURITY_VERSION_NUM >= 030000

void* modsec_init(void) {
    return msc_init();
}

void modsec_cleanup(void* modsec) {
    if (modsec) {
        msc_cleanup((ModSecurity*)modsec);
    }
}

void* modsec_create_rules_set(void) {
    return msc_create_rules_set();
}

int modsec_add_rules_file(void* rules_set, const char* file) {
    const char* error = NULL;
    int ret = msc_rules_add_file((RulesSet*)rules_set, file, &error);
    if (ret < 0 && error) {
        fprintf(stderr, "ModSecurity: Failed to load rules from %s: %s\n", file, error);
        free((void*)error);
    }
    return ret;
}

int modsec_add_rules(void* rules_set, const char* rules) {
    const char* error = NULL;
    int ret = msc_rules_add((RulesSet*)rules_set, rules, &error);
    if (ret < 0 && error) {
        fprintf(stderr, "ModSecurity: Failed to add rules: %s\n", error);
        free((void*)error);
    }
    return ret;
}

int modsec_get_rules_count(void* rules_set) {
    return msc_rules_get_reference_count((RulesSet*)rules_set);
}

void* modsec_new_transaction(void* modsec, void* rules_set, void* log_cb) {
    return msc_new_transaction((ModSecurity*)modsec, (RulesSet*)rules_set, log_cb);
}

int modsec_process_connection(void* transaction, const char* client_ip, int client_port,
                              const char* server_ip, int server_port) {
    return msc_process_connection((Transaction*)transaction, client_ip, client_port, 
                                  server_ip, server_port);
}

int modsec_process_uri(void* transaction, const char* uri, const char* protocol,
                      const char* http_version) {
    return msc_process_uri((Transaction*)transaction, uri, protocol, http_version);
}

int modsec_process_request_headers(void* transaction) {
    return msc_process_request_headers((Transaction*)transaction);
}

int modsec_add_request_header(void* transaction, const char* key, const char* value) {
    return msc_add_request_header((Transaction*)transaction, 
                                  (unsigned char*)key, (unsigned char*)value);
}

int modsec_process_request_body(void* transaction) {
    return msc_process_request_body((Transaction*)transaction);
}

int modsec_append_request_body(void* transaction, const unsigned char* body, size_t size) {
    return msc_append_request_body((Transaction*)transaction, body, size);
}

int modsec_process_response_headers(void* transaction, int status_code,
                                   const char* protocol) {
    return msc_process_response_headers((Transaction*)transaction, status_code, protocol);
}

int modsec_add_response_header(void* transaction, const char* key, const char* value) {
    return msc_add_response_header((Transaction*)transaction, 
                                   (unsigned char*)key, (unsigned char*)value);
}

int modsec_process_response_body(void* transaction) {
    return msc_process_response_body((Transaction*)transaction);
}

int modsec_append_response_body(void* transaction, const unsigned char* body, size_t size) {
    return msc_append_response_body((Transaction*)transaction, body, size);
}

int modsec_intervention(void* transaction, ModSecurityIntervention* intervention) {
    ModSecurityIntervention_t native_intervention;
    memset(&native_intervention, 0, sizeof(native_intervention));
    
    int ret = msc_intervention((Transaction*)transaction, &native_intervention);
    
    if (intervention) {
        intervention->status = native_intervention.status;
        intervention->pause = native_intervention.pause;
        intervention->url = native_intervention.url ? strdup(native_intervention.url) : NULL;
        intervention->log = native_intervention.log ? strdup(native_intervention.log) : NULL;
        intervention->disruptive = native_intervention.disruptive;
    }
    
    return ret;
}

const char* modsec_get_variable(void* transaction, const char* name) {
    return msc_get_variable((Transaction*)transaction, name);
}

const char* modsec_get_transaction_id(void* transaction) {
    return msc_get_transaction_id((Transaction*)transaction);
}

int modsec_get_rule_messages(void* transaction, char*** messages, int* count) {
    // This would need custom implementation to extract rule messages
    // For now, return empty set
    *messages = NULL;
    *count = 0;
    return 0;
}

void modsec_free_rule_messages(char** messages, int count) {
    if (messages) {
        for (int i = 0; i < count; i++) {
            free(messages[i]);
        }
        free(messages);
    }
}

int modsec_process_logging(void* transaction) {
    return msc_process_logging((Transaction*)transaction);
}

void modsec_transaction_cleanup(void* transaction) {
    if (transaction) {
        msc_transaction_cleanup((Transaction*)transaction);
    }
}

const char* modsec_get_version(void) {
    return msc_get_version();
}

void modsec_set_log_callback(void* modsec, modsec_log_cb callback, void* cb_data) {
    if (modsec && callback) {
        msc_set_log_callback((ModSecurity*)modsec, 
                            (void (*)(void*, const void*))callback, cb_data);
    }
}

#else
// ModSecurity v2 implementation (limited support)

void* modsec_init(void) {
    // For v2, we'd need to initialize differently
    return NULL;
}

void modsec_cleanup(void* modsec) {
    // No-op for v2
}

void* modsec_create_rules_set(void) {
    return NULL;
}

int modsec_add_rules_file(void* rules_set, const char* file) {
    return -1; // Not implemented for v2
}

int modsec_add_rules(void* rules_set, const char* rules) {
    return -1; // Not implemented for v2
}

int modsec_get_rules_count(void* rules_set) {
    return 0;
}

void* modsec_new_transaction(void* modsec, void* rules_set, void* log_cb) {
    return NULL;
}

int modsec_process_connection(void* transaction, const char* client_ip, int client_port,
                              const char* server_ip, int server_port) {
    return -1;
}

int modsec_process_uri(void* transaction, const char* uri, const char* protocol,
                      const char* http_version) {
    return -1;
}

int modsec_process_request_headers(void* transaction) {
    return -1;
}

int modsec_add_request_header(void* transaction, const char* key, const char* value) {
    return -1;
}

int modsec_process_request_body(void* transaction) {
    return -1;
}

int modsec_append_request_body(void* transaction, const unsigned char* body, size_t size) {
    return -1;
}

int modsec_process_response_headers(void* transaction, int status_code,
                                   const char* protocol) {
    return -1;
}

int modsec_add_response_header(void* transaction, const char* key, const char* value) {
    return -1;
}

int modsec_process_response_body(void* transaction) {
    return -1;
}

int modsec_append_response_body(void* transaction, const unsigned char* body, size_t size) {
    return -1;
}

int modsec_intervention(void* transaction, ModSecurityIntervention* intervention) {
    return 0;
}

const char* modsec_get_variable(void* transaction, const char* name) {
    return NULL;
}

const char* modsec_get_transaction_id(void* transaction) {
    return "unknown";
}

int modsec_get_rule_messages(void* transaction, char*** messages, int* count) {
    *messages = NULL;
    *count = 0;
    return 0;
}

void modsec_free_rule_messages(char** messages, int count) {
    // No-op
}

int modsec_process_logging(void* transaction) {
    return 0;
}

void modsec_transaction_cleanup(void* transaction) {
    // No-op
}

const char* modsec_get_version(void) {
    return "2.9.x";
}

void modsec_set_log_callback(void* modsec, modsec_log_cb callback, void* cb_data) {
    // Not supported in v2 wrapper
}

#endif