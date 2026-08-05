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

#include "oru_ul_pcap.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#include "xran_pkt.h"
#include "xran_pkt_cp.h"
#include "xran_pkt_api.h"

#include "common/utils/LOG/log.h"

#define ETHER_TYPE_ECPRI 0xAEFE

/* Real-time constraints (sync fwrite/fflush on the FH path previously stalled the ORU):
 *   - hot path only memcpy's into a fixed ring (never blocks on disk)
 *   - a dedicated writer thread does all fwrite/fflush/fclose
 *   - ring-full drops the sample (capture is best-effort)
 *   - never dump DL C-plane; Type-3 / PRACH only after first Type-1 UL (PUSCH) C-plane
 */
#define ORU_PCAP_LINKTYPE_ETHERNET 1
#define ORU_PCAP_FILE_BUF_SIZE (1u << 20) /* 1 MiB stdio buffer */
#define ORU_PCAP_MAX_FRAME 8192
#define ORU_PCAP_RING_SIZE 256
enum { ORU_PCAP_CHAN_ALL = 0, ORU_PCAP_CHAN_PUSCH = 1, ORU_PCAP_CHAN_PRACH = 2 };

typedef struct {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t frame_len;
  uint8_t data[ORU_PCAP_MAX_FRAME];
} oru_pcap_slot_t;

static FILE *oru_ul_pcap_fp = NULL;
static char oru_ul_pcap_file_buf[ORU_PCAP_FILE_BUF_SIZE];
static oru_pcap_slot_t oru_ul_pcap_ring[ORU_PCAP_RING_SIZE];
static pthread_mutex_t oru_ul_pcap_enq_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t oru_ul_pcap_widx = 0; /* under enq_lock */
static _Atomic uint32_t oru_ul_pcap_ridx = 0;
static uint32_t oru_ul_pcap_queued = 0; /* successful enqueues; under enq_lock */
static _Atomic uint32_t oru_ul_pcap_dropped = 0;
static _Atomic uint32_t oru_ul_pcap_written = 0;
static uint32_t oru_ul_pcap_max = 20000;
static int oru_ul_pcap_chan = ORU_PCAP_CHAN_ALL;
static _Atomic bool oru_ul_pcap_enabled = false;
static bool oru_ul_pcap_init_done = false;
static pthread_t oru_ul_pcap_thread;
static _Atomic bool oru_ul_pcap_pusch_seen = false;
static int oru_ul_pcap_prach_eaxc_offset = 0;
static struct xran_eaxcid_config oru_ul_pcap_eaxcid_config = {.mask_cuPortId = 0xF000,
                                                              .mask_bandSectorId = 0x0F00,
                                                              .mask_ccId = 0x00F0,
                                                              .mask_ruPortId = 0x000F,
                                                              .bit_cuPortId = 12,
                                                              .bit_bandSectorId = 8,
                                                              .bit_ccId = 4,
                                                              .bit_ruPortId = 0};

static bool oru_ul_pcap_inactive(void)
{
  return !atomic_load_explicit(&oru_ul_pcap_enabled, memory_order_relaxed);
}

static void *oru_ul_pcap_writer(void *arg)
{
  (void)arg;
  while (true) {
    uint32_t r = atomic_load_explicit(&oru_ul_pcap_ridx, memory_order_relaxed);
    uint32_t w;
    bool capped;
    pthread_mutex_lock(&oru_ul_pcap_enq_lock);
    w = oru_ul_pcap_widx;
    capped = oru_ul_pcap_queued >= oru_ul_pcap_max;
    pthread_mutex_unlock(&oru_ul_pcap_enq_lock);

    if (r == w) {
      if (capped)
        break;
      struct timespec sleep_ts = {.tv_sec = 0, .tv_nsec = 1000 * 1000}; /* 1 ms */
      nanosleep(&sleep_ts, NULL);
      continue;
    }

    oru_pcap_slot_t *slot = &oru_ul_pcap_ring[r % ORU_PCAP_RING_SIZE];
    struct __attribute__((packed)) {
      uint32_t ts_sec, ts_usec, incl_len, orig_len;
    } ph = {slot->ts_sec, slot->ts_usec, slot->frame_len, slot->frame_len};
    if (oru_ul_pcap_fp != NULL) {
      fwrite(&ph, sizeof(ph), 1, oru_ul_pcap_fp);
      fwrite(slot->data, 1, slot->frame_len, oru_ul_pcap_fp);
    }
    atomic_store_explicit(&oru_ul_pcap_ridx, r + 1, memory_order_release);
    uint32_t n = atomic_fetch_add_explicit(&oru_ul_pcap_written, 1, memory_order_relaxed) + 1;
    /* Periodic flush so /tmp/oru_ul.pcap is inspectable while capture runs. */
    if (oru_ul_pcap_fp != NULL && (n % 32u) == 0u)
      fflush(oru_ul_pcap_fp);
    if (n >= oru_ul_pcap_max)
      break;
  }

  if (oru_ul_pcap_fp != NULL) {
    fflush(oru_ul_pcap_fp);
    fclose(oru_ul_pcap_fp);
    oru_ul_pcap_fp = NULL;
  }
  uint32_t dropped = atomic_load_explicit(&oru_ul_pcap_dropped, memory_order_relaxed);
  uint32_t written = atomic_load_explicit(&oru_ul_pcap_written, memory_order_relaxed);
  atomic_store_explicit(&oru_ul_pcap_enabled, false, memory_order_release);
  LOG_A(HW, "ORU UL pcap writer done: wrote %u packets, dropped %u\n", written, dropped);
  return NULL;
}

void oru_ul_pcap_init_from_env(int prach_eaxc_offset)
{
  if (oru_ul_pcap_init_done)
    return;
  oru_ul_pcap_init_done = true;
  oru_ul_pcap_prach_eaxc_offset = prach_eaxc_offset;

  const char *path = getenv("ORU_UL_PCAP_PATH");
  if (path == NULL || path[0] == '\0')
    return;
  const char *max_env = getenv("ORU_UL_PCAP_MAX");
  if (max_env != NULL && max_env[0] != '\0')
    oru_ul_pcap_max = (uint32_t)strtoul(max_env, NULL, 10);
  const char *chan_env = getenv("ORU_UL_PCAP_CHAN");
  if (chan_env != NULL) {
    if (strcmp(chan_env, "pusch") == 0)
      oru_ul_pcap_chan = ORU_PCAP_CHAN_PUSCH;
    else if (strcmp(chan_env, "prach") == 0)
      oru_ul_pcap_chan = ORU_PCAP_CHAN_PRACH;
  }
  oru_ul_pcap_fp = fopen(path, "wb");
  if (oru_ul_pcap_fp == NULL) {
    LOG_E(HW, "ORU_UL_PCAP_PATH=%s could not be opened: %s\n", path, strerror(errno));
    return;
  }
  setvbuf(oru_ul_pcap_fp, oru_ul_pcap_file_buf, _IOFBF, sizeof(oru_ul_pcap_file_buf));
  struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t ver_major, ver_minor;
    int32_t thiszone;
    uint32_t sigfigs, snaplen, network;
  } gh = {0xa1b2c3d4, 2, 4, 0, 0, 65535, ORU_PCAP_LINKTYPE_ETHERNET};
  fwrite(&gh, sizeof(gh), 1, oru_ul_pcap_fp);
  /* Header alone lives in the 1 MiB stdio buffer; flush so a live 24-byte file
   * shows capture is armed even when no UL C-plane is accepted yet. */
  fflush(oru_ul_pcap_fp);

  if (pthread_create(&oru_ul_pcap_thread, NULL, oru_ul_pcap_writer, NULL) != 0) {
    LOG_E(HW, "ORU UL pcap writer thread failed: %s\n", strerror(errno));
    fclose(oru_ul_pcap_fp);
    oru_ul_pcap_fp = NULL;
    return;
  }
  pthread_detach(oru_ul_pcap_thread);
  atomic_store_explicit(&oru_ul_pcap_enabled, true, memory_order_release);
  LOG_A(HW,
        "ORU UL pcap dump enabled -> %s (max %u; U-plane chan %s; async ring %u; PRACH after first PUSCH C-plane)\n",
        path,
        oru_ul_pcap_max,
        oru_ul_pcap_chan == ORU_PCAP_CHAN_PUSCH   ? "pusch"
        : oru_ul_pcap_chan == ORU_PCAP_CHAN_PRACH ? "prach"
                                                  : "all",
        ORU_PCAP_RING_SIZE);
}

/* Hot-path enqueue: copy one Ethernet frame into the ring. Never fwrite here. */
static void oru_ul_pcap_enqueue(const uint8_t *payload, uint32_t payload_len, bool ecpri_only)
{
  if (payload == NULL || payload_len == 0 || oru_ul_pcap_inactive())
    return;

  uint32_t frame_len = ecpri_only ? payload_len + (uint32_t)sizeof(struct rte_ether_hdr) : payload_len;
  if (frame_len == 0 || frame_len > ORU_PCAP_MAX_FRAME) {
    atomic_fetch_add_explicit(&oru_ul_pcap_dropped, 1, memory_order_relaxed);
    return;
  }

  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  pthread_mutex_lock(&oru_ul_pcap_enq_lock);
  if (!atomic_load_explicit(&oru_ul_pcap_enabled, memory_order_relaxed)
      || oru_ul_pcap_queued >= oru_ul_pcap_max) {
    pthread_mutex_unlock(&oru_ul_pcap_enq_lock);
    return;
  }
  uint32_t r = atomic_load_explicit(&oru_ul_pcap_ridx, memory_order_acquire);
  if (oru_ul_pcap_widx - r >= ORU_PCAP_RING_SIZE) {
    pthread_mutex_unlock(&oru_ul_pcap_enq_lock);
    atomic_fetch_add_explicit(&oru_ul_pcap_dropped, 1, memory_order_relaxed);
    return;
  }

  oru_pcap_slot_t *slot = &oru_ul_pcap_ring[oru_ul_pcap_widx % ORU_PCAP_RING_SIZE];
  slot->ts_sec = (uint32_t)ts.tv_sec;
  slot->ts_usec = (uint32_t)(ts.tv_nsec / 1000);
  slot->frame_len = frame_len;

  const uint8_t ethertype[2] = {(ETHER_TYPE_ECPRI >> 8) & 0xff, ETHER_TYPE_ECPRI & 0xff};
  if (ecpri_only) {
    memset(slot->data, 0, 12);
    slot->data[12] = ethertype[0];
    slot->data[13] = ethertype[1];
    memcpy(slot->data + 14, payload, payload_len);
  } else if (payload_len >= sizeof(struct rte_ether_hdr)) {
    memcpy(slot->data, payload, 12);
    slot->data[12] = ethertype[0];
    slot->data[13] = ethertype[1];
    memcpy(slot->data + 14, payload + 14, payload_len - 14);
  } else {
    memcpy(slot->data, payload, payload_len);
  }

  oru_ul_pcap_widx++;
  oru_ul_pcap_queued++;
  bool hit_max = oru_ul_pcap_queued >= oru_ul_pcap_max;
  pthread_mutex_unlock(&oru_ul_pcap_enq_lock);

  if (hit_max)
    atomic_store_explicit(&oru_ul_pcap_enabled, false, memory_order_release);
}

bool oru_ul_pcap_mbuf_is_prach(struct rte_mbuf *mbuf)
{
  if (mbuf == NULL)
    return false;
  const uint8_t *frame = rte_pktmbuf_mtod(mbuf, const uint8_t *);
  uint32_t len = rte_pktmbuf_pkt_len(mbuf);
  if (len < sizeof(struct rte_ether_hdr) + sizeof(struct xran_ecpri_hdr))
    return false;
  const struct xran_ecpri_hdr *ecpri = (const struct xran_ecpri_hdr *)(frame + sizeof(struct rte_ether_hdr));
  uint8_t ant_id = 0;
  xran_decompose_cid(ecpri->ecpri_xtc_id, &oru_ul_pcap_eaxcid_config, NULL, NULL, NULL, &ant_id);
  return ant_id >= (uint8_t)oru_ul_pcap_prach_eaxc_offset;
}

void oru_ul_pcap_write_uplane(struct rte_mbuf *mbuf, bool is_prach)
{
  if (mbuf == NULL || oru_ul_pcap_inactive())
    return;
  if (is_prach && !atomic_load_explicit(&oru_ul_pcap_pusch_seen, memory_order_relaxed))
    return;
  bool chan_ok = oru_ul_pcap_chan == ORU_PCAP_CHAN_ALL
                 || (is_prach && oru_ul_pcap_chan == ORU_PCAP_CHAN_PRACH)
                 || (!is_prach && oru_ul_pcap_chan == ORU_PCAP_CHAN_PUSCH);
  if (chan_ok)
    oru_ul_pcap_enqueue(rte_pktmbuf_mtod(mbuf, const uint8_t *), rte_pktmbuf_pkt_len(mbuf), false);
}

static void oru_ul_pcap_write_cplane_bytes(const uint8_t *ecpri, uint32_t len)
{
  if (ecpri == NULL || len == 0 || oru_ul_pcap_inactive())
    return;
  oru_ul_pcap_enqueue(ecpri, len, true);
}

static bool oru_ul_pcap_want_cplane(const uint8_t *data, uint32_t len)
{
  const uint32_t ecpri_len = (uint32_t)sizeof(struct xran_ecpri_hdr);
  if (len < ecpri_len + sizeof(struct xran_cp_radioapp_common_header))
    return false;
  const struct xran_cp_radioapp_common_header *apphdr =
      (const struct xran_cp_radioapp_common_header *)(data + ecpri_len);
  const uint8_t section_type = apphdr->sectionType;
  if (section_type == XRAN_CP_SECTIONTYPE_3)
    return atomic_load_explicit(&oru_ul_pcap_pusch_seen, memory_order_relaxed);
  if (section_type != XRAN_CP_SECTIONTYPE_1)
    return false;
  uint32_t bits = rte_be_to_cpu_32(apphdr->field.all_bits);
  const uint32_t data_direction = (bits >> 31) & 1u;
  return data_direction == (uint32_t)XRAN_DIR_UL;
}

void oru_ul_pcap_cplane_begin(struct rte_mbuf *pkt, oru_ul_pcap_cplane_snap_t *snap)
{
  if (snap == NULL)
    return;
  snap->ok = false;
  snap->len = 0;
  if (pkt == NULL || oru_ul_pcap_inactive())
    return;
  uint32_t len = rte_pktmbuf_pkt_len(pkt);
  const uint8_t *src = rte_pktmbuf_mtod(pkt, const uint8_t *);
  if (len == 0 || len > sizeof(snap->data) || !oru_ul_pcap_want_cplane(src, len))
    return;
  memcpy(snap->data, src, len);
  snap->len = len;
  snap->ok = true;
}

void oru_ul_pcap_cplane_commit_pusch(oru_ul_pcap_cplane_snap_t *snap)
{
  atomic_store_explicit(&oru_ul_pcap_pusch_seen, true, memory_order_relaxed);
  if (snap != NULL && snap->ok)
    oru_ul_pcap_write_cplane_bytes(snap->data, snap->len);
  if (snap != NULL)
    snap->ok = false;
}

void oru_ul_pcap_cplane_commit_prach(oru_ul_pcap_cplane_snap_t *snap)
{
  if (snap != NULL && snap->ok)
    oru_ul_pcap_write_cplane_bytes(snap->data, snap->len);
  if (snap != NULL)
    snap->ok = false;
}
