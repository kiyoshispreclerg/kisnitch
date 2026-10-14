/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Packing and unpacking protobuf-c messages (common/pb/) the way Go's
 * protobuf does it: proto3 strings must be valid UTF-8. Shared by the
 * daemon and the UI.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: ks_pb_pack() returns a malloc'd buffer owned by the caller;
 * ks_pb_unpack() returns a message freed with
 * protobuf_c_message_free_unpacked().
 */
#ifndef KS_COMMON_PB_UTIL_H
#define KS_COMMON_PB_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <protobuf-c/protobuf-c.h>

/* Packs `m` into a malloc'd buffer (`*len` bytes). NULL on OOM. Packing
 * fails like Go's proto.Marshal if a string is not valid UTF-8. */
uint8_t *ks_pb_pack(const ProtobufCMessage *m, size_t *len);

/* proto3 strings must be valid UTF-8: Go refuses to marshal or unmarshal a
 * message otherwise. Checks every string, recursively. */
bool ks_pb_valid_utf8(const ProtobufCMessage *m);

/* Unpacks `len` bytes as `desc`, and rejects invalid UTF-8 as Go does.
 * Free with protobuf_c_message_free_unpacked(). NULL on error. */
ProtobufCMessage *ks_pb_unpack(const ProtobufCMessageDescriptor *desc,
                               const uint8_t *data, size_t len);

#endif
