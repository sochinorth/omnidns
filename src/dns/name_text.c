// SPDX-License-Identifier: MIT
/* Text <-> wire conversion of domain names (the rest of wire.h is wire.c). */
#include <errno.h>
#include <string.h>

#include "dns/wire.h"

static int parse_escape(const char **pp, uint8_t *out)
{
	const char *p = *pp;
	int v;

	if (!*p)
		return -EINVAL;
	if (*p < '0' || *p > '9') {
		*out = (uint8_t)*p;
		*pp = p + 1;
		return 0;
	}
	if (p[1] < '0' || p[1] > '9' || p[2] < '0' || p[2] > '9')
		return -EINVAL;
	v = (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
	if (v > 255)
		return -EINVAL;
	*out = (uint8_t)v;
	*pp = p + 3;
	return 0;
}

int dns_name_from_text(struct dns_name *n, const char *text)
{
	const char *p = text;
	size_t pos = 0, lab;

	if (!strcmp(text, ".") || !*text) {
		n->data[0] = 0;
		n->len = 1;
		return 0;
	}
	while (*p) {
		lab = pos++;
		if (pos >= DNS_MAX_NAME)
			return -EINVAL;
		while (*p && *p != '.') {
			uint8_t c = (uint8_t)*p++;

			if (c == '\\' && parse_escape(&p, &c))
				return -EINVAL;
			if (pos - lab > DNS_MAX_LABEL || pos + 1 >= DNS_MAX_NAME)
				return -EINVAL;
			n->data[pos++] = c;
		}
		if (pos - lab == 1)
			return -EINVAL;		/* empty label */
		n->data[lab] = (uint8_t)(pos - lab - 1);
		if (*p == '.')
			p++;
	}
	n->data[pos++] = 0;
	n->len = (uint8_t)pos;
	return 0;
}

static bool plain_char(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
	       c == '-' || c == '_' || c == '*';
}

int dns_name_to_text(const uint8_t *wire, uint8_t wire_len, char *out, size_t cap)
{
	size_t o = 0, i = 0;

	if (!cap)
		return -ENOSPC;
	while (i < wire_len && wire[i]) {
		uint8_t l = wire[i++];

		if (l > DNS_MAX_LABEL || i + l >= wire_len)
			return -EINVAL;
		if (o && o + 1 < cap)
			out[o++] = '.';
		else if (o)
			return -ENOSPC;
		for (; l; l--) {
			uint8_t c = wire[i++];

			if (c >= 'A' && c <= 'Z')
				c += 'a' - 'A';
			if (plain_char(c)) {
				if (o + 1 >= cap)
					return -ENOSPC;
				out[o++] = (char)c;
				continue;
			}
			if (o + 4 >= cap)
				return -ENOSPC;
			out[o++] = '\\';
			out[o++] = (char)('0' + c / 100);
			out[o++] = (char)('0' + c / 10 % 10);
			out[o++] = (char)('0' + c % 10);
		}
	}
	if (i >= wire_len)
		return -EINVAL;		/* missing root label */
	out[o] = 0;
	return (int)o;
}
