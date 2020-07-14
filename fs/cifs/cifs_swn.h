// SPDX-License-Identifier: GPL-2.0
/*
 * Witness Service client for CIFS
 *
 * Copyright (c) 2020 Samuel Cabrero <scabrero@samba.org>
 */

#ifndef _CIFS_SWN_H
#define _CIFS_SWN_H

struct sk_buff;
struct genl_info;

extern int cifs_swn_notify(struct sk_buff *skb, struct genl_info *info);

extern int cifs_swn_register(struct cifs_tcon *tcon, struct smb_vol *volume_info);

#endif /* _CIFS_SWN_H */
