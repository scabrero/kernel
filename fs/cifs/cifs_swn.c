// SPDX-License-Identifier: GPL-2.0
/*
 * Witness Service client for CIFS
 *
 * Copyright (c) 2020 Samuel Cabrero <scabrero@samba.org>
 */

#include <net/genetlink.h>
#include <uapi/linux/cifs/cifs_netlink.h>

#include "cifsglob.h"
#include "cifs_debug.h"
#include "netlink.h"

int cifs_swn_notify(struct sk_buff *skb, struct genl_info *info)
{
	return -EINVAL;
}

int cifs_swn_register(const char *net_name,
		      const char *share_name,
		      const char *ip_address,
		      bool net_name_notification_required,
		      bool share_name_notification_required,
		      bool ip_notification_required)
{
	struct sk_buff *skb;
	struct genlmsghdr *hdr;
	int ret;

	skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb == NULL) {
		return -ENOMEM;
	}

	hdr = genlmsg_put(skb, 0, 0, &cifs_genl_family, 0,
			  CIFS_GENL_CMD_SWN_REGISTER);
	if (hdr == NULL) {
		ret = -ENOMEM;
		goto nlmsg_fail;
	}

	if (net_name != NULL) {
		ret = nla_put_string(skb, CIFS_GENL_ATTR_SWN_NET_NAME, net_name);
		if (ret < 0) {
			goto nlmsg_fail;
		}
	}

	if (share_name != NULL) {
		ret = nla_put_string(skb, CIFS_GENL_ATTR_SWN_SHARE_NAME, share_name);
		if (ret < 0) {
			goto nlmsg_fail;
		}
	}

	if (ip_address != NULL) {
		ret = nla_put_string(skb, CIFS_GENL_ATTR_SWN_IP, ip_address);
		if (ret < 0) {
			goto nlmsg_fail;
		}
	}

	if (net_name_notification_required) {
		ret = nla_put_flag(skb, CIFS_GENL_ATTR_SWN_NET_NAME_NOTIFY);
		if (ret < 0) {
			goto nlmsg_fail;
		}
	}

	if (share_name_notification_required) {
		ret = nla_put_flag(skb,
				CIFS_GENL_ATTR_SWN_SHARE_NAME_NOTIFY);
		if (ret < 0) {
			goto nlmsg_fail;
		}
	}

	if (ip_notification_required) {
		ret = nla_put_flag(skb, CIFS_GENL_ATTR_SWN_IP_NOTIFY);
		if (ret < 0) {
			goto nlmsg_fail;
		}
	}

	genlmsg_end(skb, hdr);
	genlmsg_multicast(&cifs_genl_family, skb, 0,
			  CIFS_GENL_MCGRP_SWN, GFP_ATOMIC);

	return 0;

nlmsg_fail:
	genlmsg_cancel(skb, hdr);
	nlmsg_free(skb);
	return ret;
}
