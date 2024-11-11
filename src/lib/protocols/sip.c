/*
 * sip.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-22 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SIP

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_sip_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SIP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* ********************************************************** */

static int search_cmd(struct ndpi_detection_module_struct *ndpi_struct)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;
  const char **cs;
  size_t length;
  const char *cmds_a[] = { "Ack sip",
                           "Ack tel",
                           NULL };
  const char *cmds_b[] = { "Bye sip",
                           NULL};
  const char *cmds_c[] = { "Cancel sip",
                           "Cancel tel",
                           NULL};
  const char *cmds_i[] = { "Invite sip",
                           "Info sip",
                           NULL};
  const char *cmds_m[] = { "Message sip",
                           NULL};
  const char *cmds_n[] = { "Notify sip",
                           NULL};
  const char *cmds_o[] = { "Options sip",
                           "Options tel",
                           NULL};
  const char *cmds_p[] = { "Publish sip",
                           "Prack sip",
                           NULL};
  const char *cmds_r[] = { "Register sip",
                           "Refer sip",
                           NULL};
  const char *cmds_s[] = { "Subscribe sip",
                           "SIP/2.0", /* Reply; useful with asymmetric flows */
                           NULL};

  switch(packet_payload[0]) {
  case 'a':
  case 'A':
    cs = cmds_a;
    break;
  case 'b':
  case 'B':
    cs = cmds_b;
    break;
  case 'c':
  case 'C':
    cs = cmds_c;
    break;
  case 'i':
  case 'I':
    cs = cmds_i;
    break;
  case 'm':
  case 'M':
    cs = cmds_m;
    break;
  case 'n':
  case 'N':
    cs = cmds_n;
    break;
  case 'o':
  case 'O':
    cs = cmds_o;
    break;
  case 'p':
  case 'P':
    cs = cmds_p;
    break;
  case 'r':
  case 'R':
    cs = cmds_r;
    break;
  case 's':
  case 'S':
    cs = cmds_s;
    break;
  default:
    return 0;
  }

  while(*cs) {
    length = strlen(*cs);
    if(payload_len > length &&
       strncasecmp((const char *)packet_payload, *cs, length) == 0) {
      NDPI_LOG_DBG(ndpi_struct, "Matching with [%s]\n", *cs);
      return 1;
    }
    cs++;
  }
  return 0;
}



void ndpi_search_sip(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;

  NDPI_LOG_DBG(ndpi_struct, "Searching for SIP\n");

  if(flow->packet_counter >= 8) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  
  if(payload_len > 4) {
    /* search for STUN Turn ChannelData Prefix */
    u_int16_t message_len = ntohs(get_u_int16_t(packet->payload, 2));

    if(payload_len - 4 == message_len) {
      NDPI_LOG_DBG2(ndpi_struct, "found STUN TURN ChannelData prefix\n");
      payload_len -= 4;
      packet_payload += 4;
    }

    if(!isprint(packet_payload[0])) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
  }

  if(payload_len == 5 && memcmp(packet_payload, "hello", 5) == 0) {
    NDPI_LOG_INFO(ndpi_struct, "found sip via HELLO (kind of ping)\n");
    ndpi_int_sip_add_connection(ndpi_struct, flow);
    return;
  }

  if(payload_len >= 30) { /* Arbitrary value: SIP packets are quite big */
    if(search_cmd(ndpi_struct) == 1) {
      NDPI_LOG_INFO(ndpi_struct, "found sip command\n");
      ndpi_int_sip_add_connection(ndpi_struct, flow);
      return;
    }
  }
}

/* ********************************************************** */

void init_sip_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("SIP", ndpi_struct, *id,
				      NDPI_PROTOCOL_SIP,
				      ndpi_search_sip,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,/* Fix courtesy of Miguel Quesada <mquesadab@gmail.com> */
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

