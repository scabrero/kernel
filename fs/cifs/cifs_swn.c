// SPDX-License-Identifier: GPL-2.0
/*
 * Witness Service client for CIFS
 *
 * Copyright (c) 2020 Samuel Cabrero <scabrero@samba.org>
 */

#include <net/genetlink.h>
#include <uapi/linux/cifs/cifs_netlink.h>

#include "cifsglob.h"
#include "cifsproto.h"
#include "fscache.h"
#include "cifs_debug.h"
#include "netlink.h"

int cifs_swn_notify(struct sk_buff *skb, struct genl_info *info)
{
	return -EINVAL;
}

int cifs_swn_register(struct cifs_tcon *tcon, struct smb_vol *volume_info)
{
	const char *net_name;
	const char *share_name;
	bool net_name_notification_required = true;
	bool ip_notification_required = true;
	bool share_name_notification_required = !(tcon->capabilities & SMB2_SHARE_CAP_SCALEOUT);
	struct sk_buff *skb;
	struct genlmsghdr *hdr;
	int ret;

	net_name = extract_hostname(volume_info->UNC);
	if (IS_ERR(net_name)) {
		ret = PTR_ERR(net_name);
		cifs_dbg(FYI, "%s: failed to extract host name from target: %d\n",
			 __func__, ret);
		goto fail;
	}

	share_name = extract_sharename(volume_info->UNC);
	if (IS_ERR(share_name)) {
		ret = PTR_ERR(share_name);
		cifs_dbg(FYI, "%s: failed to extract share name from target: %d\n",
			 __func__, ret);
		goto fail;
	}

	skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb == NULL) {
		ret = -ENOMEM;
		goto fail;
	}

	hdr = genlmsg_put(skb, 0, 0, &cifs_genl_family, 0, CIFS_GENL_CMD_SWN_REGISTER);
	if (hdr == NULL) {
		ret = -ENOMEM;
		goto nlmsg_fail;
	}

	ret = nla_put_string(skb, CIFS_GENL_ATTR_SWN_NET_NAME, net_name);
	if (ret < 0) {
		goto nlmsg_fail;
	}

	ret = nla_put_string(skb, CIFS_GENL_ATTR_SWN_SHARE_NAME, share_name);
	if (ret < 0) {
		goto nlmsg_fail;
	}

	ret = nla_put(skb, CIFS_GENL_ATTR_SWN_IP, sizeof(struct sockaddr_storage),
		      &tcon->ses->server->dstaddr);
	if (ret < 0) {
		goto nlmsg_fail;
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

	if (volume_info->username != NULL) {
		ret = nla_put_string(skb, CIFS_GENL_ATTR_SWN_USER_NAME, volume_info->username);
		if (ret < 0) {
			goto nlmsg_fail;
		}
	}

	if (volume_info->password != NULL) {
		ret = nla_put_string(skb, CIFS_GENL_ATTR_SWN_PASSWORD, volume_info->password);
		if (ret < 0) {
			goto nlmsg_fail;
		}
	}

	if (volume_info->domainname != NULL) {
		ret = nla_put_string(skb, CIFS_GENL_ATTR_SWN_DOMAIN_NAME, volume_info->domainname);
		if (ret < 0) {
			goto nlmsg_fail;
		}
	}

	genlmsg_end(skb, hdr);
	genlmsg_multicast(&cifs_genl_family, skb, 0, CIFS_GENL_MCGRP_SWN, GFP_ATOMIC);

	return 0;

nlmsg_fail:
	genlmsg_cancel(skb, hdr);
	nlmsg_free(skb);
fail:
	if (!IS_ERR(net_name)) {
		kfree(net_name);
	}
	if (!IS_ERR(share_name)) {
		kfree(share_name);
	}
	return ret;
}
