/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#ifndef ORU_UL_PCAP_H
#define ORU_UL_PCAP_H

#include <stdbool.h>
#include <stdint.h>
#include <rte_mbuf.h>

/* Async UL fronthaul pcap dump (diagnostics).
 *
 * tcpdump on a kernel netdev cannot see O-RU<->DU FH: both ends are DPDK and frames go
 * VF->VF through the NIC eSwitch. Enable with ORU_UL_PCAP_PATH=/tmp/oru_ul.pcap
 * (unset = disabled, zero cost). Cap with ORU_UL_PCAP_MAX (default 20000).
 * ORU_UL_PCAP_CHAN filters U-plane: pusch|prach|all.
 */

#define ORU_UL_PCAP_CPLANE_SNAP 1024

typedef struct {
  uint8_t data[ORU_UL_PCAP_CPLANE_SNAP];
  uint32_t len;
  bool ok;
} oru_ul_pcap_cplane_snap_t;

void oru_ul_pcap_init_from_env(int prach_eaxc_offset);
bool oru_ul_pcap_mbuf_is_prach(struct rte_mbuf *mbuf);
void oru_ul_pcap_write_uplane(struct rte_mbuf *mbuf, bool is_prach);

/* Call before rte_pktmbuf_adj on C-plane RX so the eCPRI payload is still intact. */
void oru_ul_pcap_cplane_begin(struct rte_mbuf *pkt, oru_ul_pcap_cplane_snap_t *snap);
/* After accepting Type-1 UL: mark PUSCH-seen and write snap if captured. */
void oru_ul_pcap_cplane_commit_pusch(oru_ul_pcap_cplane_snap_t *snap);
/* After accepting Type-3: write snap if captured. */
void oru_ul_pcap_cplane_commit_prach(oru_ul_pcap_cplane_snap_t *snap);

#endif /* ORU_UL_PCAP_H */
