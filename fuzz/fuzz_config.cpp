#include "ndpi_api.h"
#include "ndpi_private.h"
#include "ndpi_classify.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  struct ndpi_detection_module_struct *ndpi_info_mod;
  struct ndpi_flow_struct flow;
  u_int8_t protocol_was_guessed;
  u_int32_t i;
  u_int16_t bool_value;
  NDPI_PROTOCOL_BITMASK enabled_bitmask;
  struct ndpi_lru_cache_stats lru_stats;
  struct ndpi_patricia_tree_stats patricia_stats;
  struct ndpi_automa_stats automa_stats;
  int cat;
  u_int16_t pid;
  char *protoname;
  char catname[] = "name";
  struct ndpi_flow_input_info input_info;
  ndpi_proto p, p2;
  char out[128];
  char log_ts[32];


  if(fuzzed_data.remaining_bytes() < NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS +
				     6 + /* files */
				     2 + /* Pid */
				     2 + /* Category */
				     1 + /* Tunnel */
				     1 + /* Bool value */
				     2 + /* input_info */
				     21 /* Min real data: ip length + 1 byte of L4 header */)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  ndpi_info_mod = ndpi_init_detection_module();

  set_ndpi_debug_function(ndpi_info_mod, NULL);

  NDPI_BITMASK_RESET(enabled_bitmask);
  for(i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS ; i++) {
    if(fuzzed_data.ConsumeBool())
      NDPI_BITMASK_ADD(enabled_bitmask, i);
  }
  /* TODO: ndpi_config_set protocls enabled/disabled */

  ndpi_set_user_data(ndpi_info_mod, (void *)0xabcdabcd); /* Random pointer */
  ndpi_set_user_data(ndpi_info_mod, (void *)0xabcdabcd); /* Twice to trigger overwriting */
  ndpi_get_user_data(ndpi_info_mod);

  /* TODO: ndpi_config_set */

  if(fuzzed_data.ConsumeBool())
    ndpi_set_config(ndpi_info_mod, NULL, "filename.protocols", "protos.txt");
  if(fuzzed_data.ConsumeBool())
    ndpi_set_config(ndpi_info_mod, NULL, "filename.categories", "categories.txt");
  if(fuzzed_data.ConsumeBool())
    ndpi_set_config(ndpi_info_mod, NULL, "filename.risky_domains", "risky_domains.txt");
  if(fuzzed_data.ConsumeBool())
    ndpi_set_config(ndpi_info_mod, NULL, "filename.malicious_ja3", "ja3_fingerprints.csv");
  if(fuzzed_data.ConsumeBool())
    ndpi_set_config(ndpi_info_mod, NULL, "filename.malicious_sha1", "sha1_fingerprints.csv");
  /* Note that this function is not used by ndpiReader */
  if(fuzzed_data.ConsumeBool())
    ndpi_load_ipv4_ptree(ndpi_info_mod, "ipv4_addresses.txt", NDPI_PROTOCOL_TLS);

  /* TODO: stub for geo stuff */
  ndpi_load_geoip(ndpi_info_mod, NULL, NULL);

  ndpi_finalize_initialization(ndpi_info_mod);

  /* Random protocol configuration */
  pid = fuzzed_data.ConsumeIntegralInRange<u_int16_t>(0, NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1); /* + 1 to trigger invalid pid */
  protoname = ndpi_get_proto_by_id(ndpi_info_mod, pid);
  if (protoname) {
    assert(ndpi_get_proto_by_name(ndpi_info_mod, protoname) == pid);
  }
  ndpi_map_user_proto_id_to_ndpi_id(ndpi_info_mod, pid);
  ndpi_map_ndpi_id_to_user_proto_id(ndpi_info_mod, pid);
  ndpi_set_proto_breed(ndpi_info_mod, pid, NDPI_PROTOCOL_SAFE);
  ndpi_set_proto_category(ndpi_info_mod, pid, NDPI_PROTOCOL_CATEGORY_MEDIA);
  ndpi_is_subprotocol_informative(ndpi_info_mod, pid);
  ndpi_get_proto_breed(ndpi_info_mod, pid);

  ndpi_get_proto_by_name(ndpi_info_mod, NULL); /* Error */
  ndpi_get_proto_by_name(ndpi_info_mod, "foo"); /* Invalid protocol */

  /* Custom category configuration */
  cat = fuzzed_data.ConsumeIntegralInRange(static_cast<int>(NDPI_PROTOCOL_CATEGORY_CUSTOM_1),
                                           static_cast<int>(NDPI_PROTOCOL_NUM_CATEGORIES + 1)); /* + 1 to trigger invalid cat */
  ndpi_category_set_name(ndpi_info_mod, static_cast<ndpi_protocol_category_t>(cat), catname);
  ndpi_is_custom_category(static_cast<ndpi_protocol_category_t>(cat));
  ndpi_category_get_name(ndpi_info_mod, static_cast<ndpi_protocol_category_t>(cat));
  ndpi_get_category_id(ndpi_info_mod, catname);

  ndpi_tunnel2str(static_cast<ndpi_packet_tunnel>(fuzzed_data.ConsumeIntegralInRange(static_cast<int>(ndpi_no_tunnel),
                                                                                     static_cast<int>(ndpi_gre_tunnel + 1)))); /* + 1 to trigger invalid value */

  ndpi_get_num_supported_protocols(ndpi_info_mod);
  ndpi_get_proto_defaults(ndpi_info_mod);
  ndpi_get_ndpi_num_custom_protocols(ndpi_info_mod);
  ndpi_get_ndpi_num_supported_protocols(ndpi_info_mod);

  ndpi_self_check_host_match(stdout);

  ndpi_dump_protocols(ndpi_info_mod, stdout);
  ndpi_generate_options(fuzzed_data.ConsumeIntegralInRange(0, 4), stdout);
  ndpi_dump_risks_score(stdout);

  /* Basic code to try testing this "config" */
  bool_value = fuzzed_data.ConsumeBool();
  input_info.in_pkt_dir = fuzzed_data.ConsumeIntegralInRange(0,2);
  input_info.seen_flow_beginning = !!fuzzed_data.ConsumeBool();
  memset(&flow, 0, sizeof(flow));
  std::vector<uint8_t>pkt = fuzzed_data.ConsumeRemainingBytes<uint8_t>();
  assert(pkt.size() >= 21); /* To be sure check on fuzzed_data.remaining_bytes() at the beginning is right */

  ndpi_detection_process_packet(ndpi_info_mod, &flow, pkt.data(), pkt.size(), 0, &input_info);
  p = ndpi_detection_giveup(ndpi_info_mod, &flow, &protocol_was_guessed);

  assert(p.master_protocol == ndpi_get_flow_masterprotocol(ndpi_info_mod, &flow));
  assert(p.app_protocol == ndpi_get_flow_appprotocol(ndpi_info_mod, &flow));
  assert(p.category == ndpi_get_flow_category(ndpi_info_mod, &flow));
  ndpi_get_lower_proto(p);
  ndpi_get_upper_proto(p);
  ndpi_get_flow_error_code(&flow);
  ndpi_get_flow_risk_info(&flow, out, sizeof(out), 1);
  ndpi_get_flow_ndpi_proto(ndpi_info_mod, &flow, &p2);
  ndpi_is_proto(p, NDPI_PROTOCOL_TLS);
  ndpi_http_method2str(flow.http.method);
  ndpi_get_l4_proto_name(ndpi_get_l4_proto_info(ndpi_info_mod, p.app_protocol));
  ndpi_is_subprotocol_informative(ndpi_info_mod, p.app_protocol);
  ndpi_get_http_method(ndpi_info_mod, bool_value ? &flow : NULL);
  ndpi_get_http_url(ndpi_info_mod, &flow);
  ndpi_get_http_content_type(ndpi_info_mod, &flow);
  check_for_email_address(ndpi_info_mod, 0);
  ndpi_get_flow_name(bool_value ? &flow : NULL);
  /* ndpi_guess_undetected_protocol() is a "strange" function. Try fuzzing it, here */
  if(!ndpi_is_protocol_detected(ndpi_info_mod, p)) {
    ndpi_guess_undetected_protocol(ndpi_info_mod, bool_value ? &flow : NULL,
                                   flow.l4_proto);
    if(!flow.is_ipv6) {
      /* Another "strange" function (ipv4 only): fuzz it here, for lack of a better alternative */
      ndpi_find_ipv4_category_userdata(ndpi_info_mod, flow.c_address.v4);

      ndpi_search_tcp_or_udp_raw(ndpi_info_mod, NULL, 0, ntohl(flow.c_address.v4), ntohl(flow.s_address.v4));

      ndpi_guess_undetected_protocol_v4(ndpi_info_mod, bool_value ? &flow : NULL,
                                        flow.l4_proto,
                                        flow.c_address.v4, flow.c_port,
                                        flow.s_address.v4, flow.s_port);
    } else {
      ndpi_find_ipv6_category_userdata(ndpi_info_mod, (struct in6_addr *)flow.c_address.v6);
    }
    /* Another "strange" function: fuzz it here, for lack of a better alternative */
    ndpi_search_tcp_or_udp(ndpi_info_mod, &flow);
  }
  if(!flow.is_ipv6) {
    ndpi_network_ptree_match(ndpi_info_mod, (struct in_addr *)&flow.c_address.v4);

    ndpi_risk_params params[] = { { NDPI_PARAM_HOSTNAME, flow.host_server_name},
                                  { NDPI_PARAM_ISSUER_DN, flow.host_server_name},
                                  { NDPI_PARAM_HOST_IPV4, &flow.c_address.v4} };
    ndpi_check_flow_risk_exceptions(ndpi_info_mod, 3, params);
  }
  /* TODO: stub for geo stuff */
  ndpi_get_geoip_asn(ndpi_info_mod, NULL, NULL);
  ndpi_get_geoip_country_continent(ndpi_info_mod, NULL, NULL, 0, NULL, 0);

  ndpi_free_flow_data(&flow);

  /* Get some final stats */
  for(i = 0; i < NDPI_LRUCACHE_MAX + 1; i++) /* + 1 to test invalid type */
    ndpi_get_lru_cache_stats(ndpi_info_mod, static_cast<lru_cache_type>(i), &lru_stats);
  for(i = 0; i < NDPI_PTREE_MAX + 1; i++) /* + 1 to test invalid type */
    ndpi_get_patricia_stats(ndpi_info_mod, static_cast<ptree_type>(i), &patricia_stats);
  for(i = 0; i < NDPI_AUTOMA_MAX + 1; i++) /* + 1 to test invalid type */
    ndpi_get_automa_stats(ndpi_info_mod, static_cast<automa_type>(i), &automa_stats);


  ndpi_revision();
  ndpi_get_api_version();
  ndpi_get_gcrypt_version();

  ndpi_get_ndpi_detection_module_size();
  ndpi_detection_get_sizeof_ndpi_flow_struct();
  ndpi_detection_get_sizeof_ndpi_flow_tcp_struct();
  ndpi_detection_get_sizeof_ndpi_flow_udp_struct();

  ndpi_get_tot_allocated_memory();
  ndpi_log_timestamp(log_ts, sizeof(log_ts));

  ndpi_free_geoip(ndpi_info_mod);

  ndpi_exit_detection_module(ndpi_info_mod);

  return 0;
}
