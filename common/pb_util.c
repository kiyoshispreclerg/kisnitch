/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Packing and unpacking protobuf-c messages with Go's UTF-8 rules.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/pb_util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "common/unicode.h"

uint8_t *ks_pb_pack(const ProtobufCMessage *m, size_t *len)
{
    if (!ks_pb_valid_utf8(m)) {
        ks_debug("protobuf: %s has invalid UTF-8 strings", m->descriptor->name);
        return NULL;
    }
    size_t n = protobuf_c_message_get_packed_size(m);
    uint8_t *buf = malloc(n ? n : 1);
    if (buf == NULL)
        return NULL;
    *len = protobuf_c_message_pack(m, buf);
    return buf;
}

static bool str_ok(const char *s)
{
    return s == NULL || ks_utf8_valid(s, strlen(s));
}

bool ks_pb_valid_utf8(const ProtobufCMessage *m)
{
    const ProtobufCMessageDescriptor *d = m->descriptor;
    const char *base = (const char *)m;
    for (unsigned i = 0; i < d->n_fields; i++) {
        const ProtobufCFieldDescriptor *f = &d->fields[i];
        if (f->type != PROTOBUF_C_TYPE_STRING && f->type != PROTOBUF_C_TYPE_MESSAGE)
            continue;
        if (f->flags & PROTOBUF_C_FIELD_FLAG_ONEOF) {
            uint32_t which;
            memcpy(&which, base + f->quantifier_offset, sizeof(which));
            if (which != f->id)
                continue;
        }
        if (f->label == PROTOBUF_C_LABEL_REPEATED) {
            size_t n;
            void *const *arr;
            memcpy(&n, base + f->quantifier_offset, sizeof(n));
            memcpy(&arr, base + f->offset, sizeof(arr));
            for (size_t j = 0; j < n; j++) {
                if (f->type == PROTOBUF_C_TYPE_STRING ? !str_ok(arr[j])
                    : (arr[j] != NULL && !ks_pb_valid_utf8(arr[j])))
                    return false;
            }
        } else {
            const void *v;
            memcpy(&v, base + f->offset, sizeof(v));
            if (f->type == PROTOBUF_C_TYPE_STRING ? !str_ok(v)
                : (v != NULL && !ks_pb_valid_utf8(v)))
                return false;
        }
    }
    return true;
}

ProtobufCMessage *ks_pb_unpack(const ProtobufCMessageDescriptor *desc,
                               const uint8_t *data, size_t len)
{
    ProtobufCMessage *m = protobuf_c_message_unpack(desc, NULL, len, data);
    if (m != NULL && !ks_pb_valid_utf8(m)) {
        protobuf_c_message_free_unpacked(m, NULL);
        return NULL;
    }
    return m;
}
