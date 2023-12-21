/* SPDX-FileCopyrightText: 2023 John Scott <jscott@posteo.net>
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
/* The order of the headers here is important. */
#include <windows.h>
#include <winldap.h>
#include <winber.h>
/* It is important to note that this program uses some functions
 * the OpenLDAP folks consider deprecated in their implementation. */

int main(void) {
	if(!setlocale(LC_ALL, "")) {
		fputs("Failed to enable default locale\n", stderr);
		exit(EXIT_FAILURE);
	}

	LDAP *const ldp = ldap_init("localhost", 389);
	if(!ldp) {
		fputs("Failed to initialize LDAP\n", stderr);
		exit(EXIT_FAILURE);
	}
	if(ldap_set_option(ldp, LDAP_OPT_PROTOCOL_VERSION, &(int){LDAP_VERSION3})) {
		ldap_perror(ldp, "Failed to enable LDAP v3");
		if(ldap_unbind_s(ldp)) {
			fputs("Failed to unbind\n", stderr);
		}
		exit(EXIT_FAILURE);
	}
	if(ldap_connect(ldp, NULL)) {
		ldap_perror(ldp, "Failed to connect to LDAP server");
		if(ldap_unbind_s(ldp)) {
			fputs("Failed to unbind\n", stderr);
		}
		exit(EXIT_FAILURE);
	}

	LDAPMessage *results = NULL;
	if(ldap_search_ext_s(ldp, "DC=localhost", LDAP_SCOPE_SUBTREE, "(objectClass=*)", NULL, false, NULL, NULL, NULL, LDAP_NO_LIMIT, &results)) {
		ldap_perror(ldp, "Failed to search");
		if(ldap_unbind_s(ldp)) {
			fputs("Failed to unbind\n", stderr);
		}
		ldap_msgfree(results);
		exit(2);
	}

	for(LDAPMessage *entry = ldap_first_entry(ldp, results); entry; entry = ldap_next_entry(ldp, entry)) {
		char *const dn = ldap_get_dn(ldp, entry);
		if(!dn) {
			fputs("Failed to allocate memory", stderr);
unbind_and_free:
			if(ldap_unbind_s(ldp)) {
				fputs("Failed to unbind\n", stderr);
			}
			ldap_msgfree(results);
			exit(EXIT_FAILURE);
		}
		if(printf("\t%s\n", dn) < 0) {
			fputs("Failed to print DN\n", stderr);
			goto unbind_and_free;
		}

		BerElement *cookie = NULL;
		for(char *attrname = ldap_first_attribute(ldp, entry, &cookie); attrname; attrname = ldap_next_attribute(ldp, entry, cookie)) {
			struct berval **const attrvals = ldap_get_values_len(ldp, entry, attrname);
			if(!attrvals) {
				ldap_perror(ldp, "Failed to get attribute values");
				ldap_memfree(attrname);
				goto unbind_and_free;
			}

			for(size_t i = 0; attrvals[i]; i++) {
				if(printf("%s: ", attrname) < 0
				|| fwrite(attrvals[i]->bv_val, 1, attrvals[i]->bv_len, stdout) < attrvals[i]->bv_len
				|| putchar('\n') == EOF) {
					fputs("Failed to print attribute value\n", stderr);
					ldap_memfree(attrname);
					ber_bvecfree(attrvals);
					goto unbind_and_free;
				}
			}
			ldap_memfree(attrname);
			ber_bvecfree(attrvals);
		}
		ber_free(cookie, 0);
	}
}
