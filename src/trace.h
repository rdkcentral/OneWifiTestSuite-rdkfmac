/* SPDX-License-Identifier: GPL-2.0 */
/*
* Portions of this file
* Copyright(c) 2016-2017 Intel Deutschland GmbH
* Copyright (C) 2018 - 2019 Intel Corporation
*/

#if !defined(__MAC80211_DRIVER_TRACE) || defined(TRACE_HEADER_MULTI_READ)
#define __MAC80211_DRIVER_TRACE

#include <linux/tracepoint.h>
#include <net/mac80211.h>
#include "rdkfmac.h"

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mac80211

#define MAXNAME		32
#define LOCAL_ENTRY	__array(char, wiphy_name, 32)
#define LOCAL_ASSIGN	strlcpy(__entry->wiphy_name, wiphy_name(local->hw.wiphy), MAXNAME)
#define LOCAL_PR_FMT	"%s"
#define LOCAL_PR_ARG	__entry->wiphy_name

#define STA_ENTRY	__array(char, sta_addr, ETH_ALEN)
#define STA_ASSIGN	(sta ? memcpy(__entry->sta_addr, sta->addr, ETH_ALEN) : memset(__entry->sta_addr, 0, ETH_ALEN))
#define STA_NAMED_ASSIGN(s)	memcpy(__entry->sta_addr, (s)->addr, ETH_ALEN)
#define STA_PR_FMT	" sta:%pM"
#define STA_PR_ARG	__entry->sta_addr

#define VIF_ENTRY	__field(enum nl80211_iftype, vif_type) __field(void *, sdata)	\
			__field(bool, p2p)						\
			__string(vif_name, sdata->name)
#define VIF_ASSIGN	__entry->vif_type = sdata->vif.type; __entry->sdata = sdata;	\
			__entry->p2p = sdata->vif.p2p;					\
			__assign_str(vif_name, sdata->name)
#define VIF_PR_FMT	" vif:%s(%d%s)"
#define VIF_PR_ARG	__get_str(vif_name), __entry->vif_type, __entry->p2p ? "/p2p" : ""

#define CHANDEF_ENTRY	__field(u32, control_freq)					\
			__field(u32, chan_width)					\
			__field(u32, center_freq1)					\
			__field(u32, center_freq2)
#define CHANDEF_ASSIGN(c)							\
			__entry->control_freq = (c) ? ((c)->chan ? (c)->chan->center_freq : 0) : 0;	\
			__entry->chan_width = (c) ? (c)->width : 0;			\
			__entry->center_freq1 = (c) ? (c)->center_freq1 : 0;		\
			__entry->center_freq2 = (c) ? (c)->center_freq2 : 0;
#define CHANDEF_PR_FMT	" control:%d MHz width:%d center: %d/%d MHz"
#define CHANDEF_PR_ARG	__entry->control_freq, __entry->chan_width,			\
			__entry->center_freq1, __entry->center_freq2

#define MIN_CHANDEF_ENTRY								\
			__field(u32, min_control_freq)					\
			__field(u32, min_chan_width)					\
			__field(u32, min_center_freq1)					\
			__field(u32, min_center_freq2)

#define MIN_CHANDEF_ASSIGN(c)								\
			__entry->min_control_freq = (c)->chan ? (c)->chan->center_freq : 0;	\
			__entry->min_chan_width = (c)->width;				\
			__entry->min_center_freq1 = (c)->center_freq1;			\
			__entry->min_center_freq2 = (c)->center_freq2;
#define MIN_CHANDEF_PR_FMT	" min_control:%d MHz min_width:%d min_center: %d/%d MHz"
#define MIN_CHANDEF_PR_ARG	__entry->min_control_freq, __entry->min_chan_width,	\
			__entry->min_center_freq1, __entry->min_center_freq2

#define CHANCTX_ENTRY	CHANDEF_ENTRY							\
			MIN_CHANDEF_ENTRY						\
			__field(u8, rx_chains_static)					\
			__field(u8, rx_chains_dynamic)
#define CHANCTX_ASSIGN	CHANDEF_ASSIGN(&ctx->conf.def)					\
			MIN_CHANDEF_ASSIGN(&ctx->conf.min_def)				\
			__entry->rx_chains_static = ctx->conf.rx_chains_static;		\
			__entry->rx_chains_dynamic = ctx->conf.rx_chains_dynamic
#define CHANCTX_PR_FMT	CHANDEF_PR_FMT MIN_CHANDEF_PR_FMT " chains:%d/%d"
#define CHANCTX_PR_ARG	CHANDEF_PR_ARG,	MIN_CHANDEF_PR_ARG,				\
			__entry->rx_chains_static, __entry->rx_chains_dynamic

#define KEY_ENTRY	__field(u32, cipher)						\
			__field(u8, hw_key_idx)						\
			__field(u8, flags)						\
			__field(s8, keyidx)
#define KEY_ASSIGN(k)	__entry->cipher = (k)->cipher;					\
			__entry->flags = (k)->flags;					\
			__entry->keyidx = (k)->keyidx;					\
			__entry->hw_key_idx = (k)->hw_key_idx;
#define KEY_PR_FMT	" cipher:0x%x, flags=%#x, keyidx=%d, hw_key_idx=%d"
#define KEY_PR_ARG	__entry->cipher, __entry->flags, __entry->keyidx, __entry->hw_key_idx

#define AMPDU_ACTION_ENTRY	__field(enum ieee80211_ampdu_mlme_action,		\
					ieee80211_ampdu_mlme_action)			\
				STA_ENTRY						\
				__field(u16, tid)					\
				__field(u16, ssn)					\
				__field(u16, buf_size)					\
				__field(bool, amsdu)					\
				__field(u16, timeout)					\
				__field(u16, action)
#define AMPDU_ACTION_ASSIGN	STA_NAMED_ASSIGN(params->sta);				\
				__entry->tid = params->tid;				\
				__entry->ssn = params->ssn;				\
				__entry->buf_size = params->buf_size;			\
				__entry->amsdu = params->amsdu;				\
				__entry->timeout = params->timeout;			\
				__entry->action = params->action;
#define AMPDU_ACTION_PR_FMT	STA_PR_FMT " tid %d, ssn %d, buf_size %u, amsdu %d, timeout %d action %d"
#define AMPDU_ACTION_PR_ARG	STA_PR_ARG, __entry->tid, __entry->ssn,			\
				__entry->buf_size, __entry->amsdu, __entry->timeout,	\
				__entry->action

#endif /* !__MAC80211_DRIVER_TRACE || TRACE_HEADER_MULTI_READ */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace
#include <trace/define_trace.h>
