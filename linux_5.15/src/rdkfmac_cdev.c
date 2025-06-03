#include "rdkfmac.h"

struct rdkfmac_device_data g_char_device;
static DECLARE_WAIT_QUEUE_HEAD(rdkfmac_rq); 
static wlan_emu_msg_data_t *pop_from_char_device(void);
static unsigned int get_list_entries_count_in_char_device(void);
static bool  rdkfmac_emu80211_close = true;

const char *rdkfmac_cfg80211_ops_type_to_string(wlan_emu_cfg80211_ops_type_t type)
{
#define CFG80211_TO_S(x) case x: return #x;
	switch (type) {
		CFG80211_TO_S(wlan_emu_cfg80211_ops_type_none)
		CFG80211_TO_S(wlan_emu_cfg80211_ops_type_add_intf)
		CFG80211_TO_S(wlan_emu_cfg80211_ops_type_del_intf)
		CFG80211_TO_S(wlan_emu_cfg80211_ops_type_change_intf)
		CFG80211_TO_S(wlan_emu_cfg80211_ops_type_start_ap)
		CFG80211_TO_S(wlan_emu_cfg80211_ops_type_change_beacon)
		CFG80211_TO_S(wlan_emu_cfg80211_ops_type_stop_ap)
		default:
			break;
	}

	return "wlan_emu_cfg80211_ops_type_unknown";
}

const char *rdkfmac_mac80211_ops_type_to_string(wlan_emu_mac80211_ops_type_t type)
{
#define MAC80211_TO_S(x) case x: return #x;
	switch (type) {
		MAC80211_TO_S(wlan_emu_mac80211_ops_type_none)
		MAC80211_TO_S(wlan_emu_mac80211_ops_type_tx)
		MAC80211_TO_S(wlan_emu_mac80211_ops_type_start)
		MAC80211_TO_S(wlan_emu_mac80211_ops_type_stop)
		MAC80211_TO_S(wlan_emu_mac80211_ops_type_add_intf)
		MAC80211_TO_S(wlan_emu_mac80211_ops_type_change_intf)
		MAC80211_TO_S(wlan_emu_mac80211_ops_type_remove_intf)
		MAC80211_TO_S(wlan_emu_mac80211_ops_type_config)
		MAC80211_TO_S(wlan_emu_mac80211_ops_type_bss_info_changed)
		MAC80211_TO_S(wlan_emu_mac80211_ops_type_start_ap)
		MAC80211_TO_S(wlan_emu_mac80211_ops_type_stop_ap)
		default:
			break;
	}

	return "wlan_emu_mac80211_ops_type_unknown";
}

const char *rdkfmac_emu80211_ops_type_to_string(wlan_emu_emu80211_ops_type_t type)
{
#define EMU80211_TO_S(x) case x: return #x;
	switch (type) {
		EMU80211_TO_S(wlan_emu_emu80211_ops_type_none)
		EMU80211_TO_S(wlan_emu_emu80211_ops_type_tctrl)
		EMU80211_TO_S(wlan_emu_emu80211_ops_type_close)
		default:
			break;
	}

	return "wlan_emu_emu80211_ops_type_unknown";
}


static unsigned int rdkfmac_poll(struct file *filp, struct poll_table_struct *wait)
{
	__poll_t mask = 0;

	poll_wait(filp, &rdkfmac_rq, wait);
 
	if (get_list_entries_count_in_char_device() != 0) { 
			mask |= (POLLIN | POLLRDNORM);
	}

	return mask;
}

void push_to_char_device(wlan_emu_msg_data_t *data)
{
	wlan_emu_msg_data_entry_t	*entry;
	wlan_emu_msg_data_t	*spec;
	char	str_spec_type[32];
	char	str_ops[128];

	// do not push to list if nobody is listening
	if (g_char_device.num_inst == 0) {
		return;
	}

	if (rdkfmac_emu80211_close == true)  {
		return;
	}

	entry = kmalloc(sizeof(wlan_emu_msg_data_entry_t), GFP_KERNEL);
	spec = kmalloc(sizeof(wlan_emu_msg_data_t), GFP_KERNEL);
	entry->spec = spec;

	memcpy(spec, data, sizeof(wlan_emu_msg_data_t));

	switch (spec->type) {
		case wlan_emu_msg_type_cfg80211:
			strcpy(str_spec_type, "cfg80211");
			strcpy(str_ops, rdkfmac_cfg80211_ops_type_to_string(spec->u.cfg80211.ops));
			break;

		case wlan_emu_msg_type_mac80211:
			strcpy(str_spec_type, "mac80211");
			strcpy(str_ops, rdkfmac_mac80211_ops_type_to_string(spec->u.mac80211.ops));
			break;

		case wlan_emu_msg_type_emu80211:
			strcpy(str_spec_type, "emu80211");
			strcpy(str_ops, rdkfmac_emu80211_ops_type_to_string(spec->u.emu80211.ops));
			break;

		case wlan_emu_msg_type_webconfig:
			strcpy(str_spec_type, "webconfig");
			strcpy(str_ops, "onewifi_webconfig");
			break;

		default:
			break;
	}

	if ((spec->type != wlan_emu_msg_type_webconfig) && (spec->type != wlan_emu_msg_type_frm80211)) {
		printk("%s:%d: pushing data to queue, type: %s ops: %s current size: %d\n", __func__, __LINE__,
			str_spec_type, str_ops, get_list_entries_count_in_char_device());
	}
	list_add(&entry->list_entry, g_char_device.list_tail);
	g_char_device.list_tail = &entry->list_entry;

	wake_up_interruptible(&rdkfmac_rq);
}

void push_to_rdkfmac_device(wlan_emu_msg_data_t *data)
{
	unsigned char *cmd_buffer;
	unsigned int count = 0;
	unsigned int buff_length = 0;
	heart_beat_data_t heart_beat_data;
	mac_update_t mac_update;

	if (data->type != wlan_emu_msg_type_emu80211) {
		printk("%s:%d: received invalid control data\n", __func__, __LINE__);
		return;
	}

	if (data->u.emu80211.ops != wlan_emu_emu80211_ops_type_cmnd) {
		printk("%s:%d: received %d, invalid ops for emu80211\n", __func__, __LINE__, data->u.emu80211.ops);
		return;
	}

	switch (data->u.emu80211.u.cmd.type) {
		case wlan_emu_emu80211_cmd_radiotap:
			buff_length = data->u.emu80211.u.cmd.buff_len;
			cmd_buffer = kmalloc(sizeof(data->u.emu80211.u.cmd.cmd_buffer), GFP_KERNEL);
			if (cmd_buffer == NULL) {
				return;
			}
			memcpy(cmd_buffer, data->u.emu80211.u.cmd.cmd_buffer, sizeof(data->u.emu80211.u.cmd.cmd_buffer));

			memcpy(&heart_beat_data.mac, &cmd_buffer[count], sizeof(heart_beat_data.mac));
			count += sizeof(heart_beat_data.mac);

			memcpy(&heart_beat_data.rssi, &cmd_buffer[count], sizeof(heart_beat_data.rssi));
			count += sizeof(heart_beat_data.rssi);

			printk("%s:%d rssi : %d for MAC : %pM\n", __func__, __LINE__, heart_beat_data.rssi, heart_beat_data.mac);
/*
			for (count = 0; count < buff_length; count++ ) {
				printk(" %02X", cmd_buffer[count]);
			}
*/
			update_heartbeat_data(&heart_beat_data);
			kfree(cmd_buffer);
		break;
		case wlan_emu_emu80211_cmd_mac_update:
			buff_length = data->u.emu80211.u.cmd.buff_len;
			cmd_buffer = kmalloc(sizeof(data->u.emu80211.u.cmd.cmd_buffer), GFP_KERNEL);
			if (cmd_buffer == NULL) {
				return;
			}
			memcpy(cmd_buffer, data->u.emu80211.u.cmd.cmd_buffer, sizeof(data->u.emu80211.u.cmd.cmd_buffer));
			memcpy(&mac_update.old_mac, &cmd_buffer[count], sizeof(mac_update.old_mac));
			count += sizeof(mac_update.old_mac);
			memcpy(&mac_update.new_mac, &cmd_buffer[count], sizeof(mac_update.new_mac));
			count += sizeof(mac_update.new_mac);
			memcpy(&mac_update.bridge_name, &cmd_buffer[count], sizeof(mac_update.bridge_name));
			count += sizeof(mac_update.bridge_name);
/*
			for (count = 0; count < buff_length; count++ ) {
				printk(" %02X", cmd_buffer[count]);
			}
*/
			update_sta_new_mac(&mac_update);
			kfree(cmd_buffer);
		break;
		default:
		break;
	}
	return;

}

static void handle_emu80211_msg_w(wlan_emu_msg_data_t *spec) {
	switch (spec->u.emu80211.ops) {
		case wlan_emu_emu80211_ops_type_tctrl:
			if (spec->u.emu80211.u.ctrl.ctrl == wlan_emu_emu80211_ctrl_tstart) {
				rdkfmac_emu80211_close = false;
			} else if (spec->u.emu80211.u.ctrl.ctrl == wlan_emu_emu80211_ctrl_tstop) {
				rdkfmac_emu80211_close = true;
			}
			push_to_char_device(spec);
			break;
		case wlan_emu_emu80211_ops_type_close:
			push_to_char_device(spec);
			break;
		case wlan_emu_emu80211_ops_type_cmnd:
			push_to_rdkfmac_device(spec);
			break;

		default:
			break;
	}
	return;
}

static void handle_frm80211_msg_w(char *read_buff, size_t size) {
	wlan_emu_msg_data_t *frm80211_msg;
	struct ieee80211_hdr *hdr;
	unsigned int msg_ops_type = 0;
	unsigned short fc, type, stype;
	const unsigned char rfc1042_hdr[ETH_ALEN] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
	unsigned char *tmp_frame_buf;
	unsigned int data_header_len = 0;

	frm80211_msg = kzalloc(sizeof(wlan_emu_msg_data_t), GFP_KERNEL);
	if (frm80211_msg == NULL) {
		printk("%s:%d NULL Pointer\n", __func__, __LINE__);
		return;
	}

	memcpy(&frm80211_msg->type, read_buff, sizeof(wlan_emu_msg_type_t));
	read_buff += sizeof(wlan_emu_msg_type_t);

	if (frm80211_msg->type != wlan_emu_msg_type_frm80211) {
		printk("%s:%d Invalid type\n", __func__, __LINE__);
		kfree(frm80211_msg);
		return;
	}

//writing dummy value == 0
	memcpy(&frm80211_msg->u.frm80211.ops, &msg_ops_type, sizeof(wlan_emu_cfg80211_ops_type_t));
	read_buff += sizeof(wlan_emu_cfg80211_ops_type_t);

	memcpy(&frm80211_msg->u.frm80211.u.frame.frame_len, read_buff, sizeof(unsigned int));
	read_buff += sizeof(unsigned int);

	memcpy(&frm80211_msg->u.frm80211.u.frame.macaddr, read_buff, ETH_ALEN);
	read_buff += ETH_ALEN;

	memcpy(&frm80211_msg->u.frm80211.u.frame.client_macaddr, read_buff, ETH_ALEN);
	read_buff += ETH_ALEN;

	frm80211_msg->u.frm80211.u.frame.frame = kzalloc(frm80211_msg->u.frm80211.u.frame.frame_len, GFP_KERNEL);
	if (frm80211_msg->u.frm80211.u.frame.frame == NULL) {
		printk("%s:%d NULL Pointer\n", __func__, __LINE__);
		kfree(frm80211_msg);
		return;
	}

	memcpy(frm80211_msg->u.frm80211.u.frame.frame, read_buff, frm80211_msg->u.frm80211.u.frame.frame_len);
	read_buff += frm80211_msg->u.frm80211.u.frame.frame_len;

	hdr = (struct ieee80211_hdr *)frm80211_msg->u.frm80211.u.frame.frame;
	fc = le16_to_cpu(hdr->frame_control);
	type = WLAN_FC_GET_TYPE(fc);

	if (type == WLAN_FC_TYPE_MGMT) {
		stype = WLAN_FC_GET_STYPE(fc);
		switch (stype) {
			case WLAN_FC_STYPE_PROBE_REQ:
				msg_ops_type = wlan_emu_frm80211_ops_type_prb_req;
				break;
			case WLAN_FC_STYPE_PROBE_RESP:
				msg_ops_type = wlan_emu_frm80211_ops_type_prb_resp;
				break;
			case WLAN_FC_STYPE_ASSOC_REQ:
				msg_ops_type = wlan_emu_frm80211_ops_type_assoc_req;
				break;
			case WLAN_FC_STYPE_ASSOC_RESP:
				msg_ops_type = wlan_emu_frm80211_ops_type_assoc_resp;
				break;
			case WLAN_FC_STYPE_AUTH:
				msg_ops_type = wlan_emu_frm80211_ops_type_auth;
				break;
			case WLAN_FC_STYPE_DEAUTH:
				msg_ops_type = wlan_emu_frm80211_ops_type_deauth;
				break;
			case WLAN_FC_STYPE_DISASSOC:
				msg_ops_type = wlan_emu_frm80211_ops_type_disassoc;
				break;
			case WLAN_FC_STYPE_ACTION:
				msg_ops_type = wlan_emu_frm80211_ops_type_action;
				break;
			case WLAN_FC_STYPE_REASSOC_REQ:
				msg_ops_type = wlan_emu_frm80211_ops_type_reassoc_req;
				break;
			case WLAN_FC_STYPE_REASSOC_RESP:
				msg_ops_type = wlan_emu_frm80211_ops_type_reassoc_resp;
				break;
			default:
				printk("%s:%d Invalid fc type : %d\n", __func__, __LINE__, stype);
				kfree(frm80211_msg->u.frm80211.u.frame.frame);
				kfree(frm80211_msg);
				return;
		}
	} else if (type == WLAN_FC_TYPE_DATA) {
		data_header_len = ieee80211_hdrlen(hdr->frame_control);
		if (frm80211_msg->u.frm80211.u.frame.frame_len < data_header_len + sizeof(rfc1042_hdr) + 2) {
			kfree(frm80211_msg->u.frm80211.u.frame.frame);
			kfree(frm80211_msg);
			return;
		}

		tmp_frame_buf =  (unsigned char *)frm80211_msg->u.frm80211.u.frame.frame;
		tmp_frame_buf += data_header_len;

		if (memcmp(tmp_frame_buf, rfc1042_hdr, sizeof(rfc1042_hdr)) != 0) {
			kfree(frm80211_msg->u.frm80211.u.frame.frame);
			kfree(frm80211_msg);
			return;
		}

		tmp_frame_buf += sizeof(rfc1042_hdr);
		if (((tmp_frame_buf[0] << 8) | tmp_frame_buf[1]) != ETH_P_PAE) {
			kfree(frm80211_msg->u.frm80211.u.frame.frame);
			kfree(frm80211_msg);
			return;
		} else {
			msg_ops_type = wlan_emu_frm80211_ops_type_eapol;
		}
	}

	//updating the final correct value
	memcpy(&frm80211_msg->u.frm80211.ops, &msg_ops_type, sizeof(wlan_emu_cfg80211_ops_type_t));

	push_to_char_device(frm80211_msg);
	kfree(frm80211_msg);
	return;
}


static ssize_t rdkfmac_write(struct file *file, const char __user *user_buffer,
					size_t size, loff_t * offset)
{
	wlan_emu_msg_data_t *pSpec;
	ssize_t sz;
	char *read_buff;

	pSpec = kmalloc(sizeof(wlan_emu_msg_data_t), GFP_KERNEL);
	read_buff = kmalloc(size, GFP_KERNEL);
	memset(read_buff, 0, size);
	if (copy_from_user(read_buff, user_buffer, size)) {
		printk("%s:%d: potential copy error\n", __func__, __LINE__);
		kfree(pSpec);
		kfree(read_buff);
		return 0;
	}

	memcpy((char*)&pSpec->type, read_buff, sizeof(wlan_emu_msg_type_t));
	switch (pSpec->type) {
		case wlan_emu_msg_type_frm80211:
			handle_frm80211_msg_w(read_buff, size);
			sz = size;
			break;
		case wlan_emu_msg_type_emu80211:
			memcpy(pSpec, read_buff, sizeof(wlan_emu_msg_data_t));
			handle_emu80211_msg_w(pSpec);
			sz = sizeof(wlan_emu_msg_data_t);
			break;
		case wlan_emu_msg_type_webconfig:
			memcpy(pSpec, read_buff, sizeof(wlan_emu_msg_data_t));
			push_to_char_device(pSpec);
			sz = sizeof(wlan_emu_msg_data_t);
			break;
		default:
			printk("%s:%d Invalid read operation\n",__func__, __LINE__);
			sz = 0;
			break;
	}

	kfree(read_buff);
	kfree(pSpec);
	return sz;
}

static void fill_cfg80211_acl_data(char *f_tmp, size_t *push_len, wlan_emu_msg_data_t *spec) {
	const struct cfg80211_acl_data *acl;

	acl = spec->u.cfg80211.u.start_ap.ap_params.acl;

	if (acl) {
		size_t total_size = struct_size(acl, mac_addrs, spec->u.cfg80211.u.start_ap.ap_params.acl->n_acl_entries);

		memcpy(f_tmp, &total_size, sizeof(size_t));
		f_tmp += sizeof(size_t);
		*push_len += sizeof(size_t);

		memcpy(f_tmp, spec->u.cfg80211.u.start_ap.ap_params.acl, total_size);
		f_tmp += total_size;
		push_len += total_size;
	}

	return;
}

static void fill_cfg80211_crypto(char *f_tmp, size_t *push_len, wlan_emu_msg_data_t *spec) {

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.wpa_versions), sizeof(u32));
	f_tmp += sizeof(u32);
	*push_len += sizeof(u32);

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.cipher_group), sizeof(u32));
	f_tmp += sizeof(u32);
	*push_len += sizeof(u32);

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.n_ciphers_pairwise), sizeof(int));
	f_tmp += sizeof(int);
	*push_len += sizeof(int);

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.ciphers_pairwise), (spec->u.cfg80211.u.start_ap.ap_params.crypto.n_ciphers_pairwise)*sizeof(u32));
	f_tmp += (spec->u.cfg80211.u.start_ap.ap_params.crypto.n_ciphers_pairwise)*sizeof(u32);
	*push_len += (spec->u.cfg80211.u.start_ap.ap_params.crypto.n_ciphers_pairwise)*sizeof(u32);

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.n_akm_suites), sizeof(int));
	f_tmp += sizeof(int);
	*push_len += sizeof(int);

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.akm_suites), (spec->u.cfg80211.u.start_ap.ap_params.crypto.n_akm_suites)*sizeof(u32));
	f_tmp += (spec->u.cfg80211.u.start_ap.ap_params.crypto.n_akm_suites)*sizeof(u32);
	*push_len += (spec->u.cfg80211.u.start_ap.ap_params.crypto.n_akm_suites)*sizeof(u32);

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.control_port), sizeof(bool));
	f_tmp += sizeof(bool);
	*push_len += sizeof(bool);

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.control_port_ethertype), sizeof(__be16));
	f_tmp += sizeof(__be16);
	*push_len += sizeof(__be16);

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.control_port_no_encrypt), sizeof(bool));
	f_tmp += sizeof(bool);
	*push_len += sizeof(bool);

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.control_port_over_nl80211), sizeof(bool));
	f_tmp += sizeof(bool);
	*push_len += sizeof(bool);

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.psk), WLAN_PMK_LEN);
	f_tmp += WLAN_PMK_LEN;
	*push_len += WLAN_PMK_LEN;

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.sae_pwd_len), sizeof(u8));
	f_tmp += sizeof(u8);
	*push_len += sizeof(u8);

	memcpy(f_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.crypto.sae_pwd), spec->u.cfg80211.u.start_ap.ap_params.crypto.sae_pwd_len);
	f_tmp += spec->u.cfg80211.u.start_ap.ap_params.crypto.sae_pwd_len;
	*push_len += spec->u.cfg80211.u.start_ap.ap_params.crypto.sae_pwd_len;

	return;
}

void handle_cfg80211_msg_start_ap(wlan_emu_msg_data_t *spec, ssize_t *len, u8 *s_tmp) {
	if ((spec == NULL) || (s_tmp == NULL)) {
		printk(KERN_INFO "%s:%d: NULL Pointer \n", __func__, __LINE__);
		return;
	}

		memcpy(s_tmp, &spec->type, sizeof(wlan_emu_msg_type_t));
		s_tmp += sizeof(wlan_emu_msg_type_t);
		*len += sizeof(wlan_emu_msg_type_t);

		memcpy(s_tmp, &spec->u.cfg80211.ops, sizeof(wlan_emu_cfg80211_ops_type_t));
		s_tmp += sizeof(wlan_emu_cfg80211_ops_type_t);
		*len += sizeof(wlan_emu_cfg80211_ops_type_t);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ifindex), sizeof(int));
		s_tmp += sizeof(int);
		*len += sizeof(int);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.phy_index), sizeof(int));
		s_tmp += sizeof(int);
		*len += sizeof(int);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.chandef), sizeof(struct cfg80211_chan_def));
		s_tmp += sizeof(struct cfg80211_chan_def);
		*len += sizeof(struct cfg80211_chan_def);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.beacon.ftm_responder), sizeof(u8));
		s_tmp += sizeof(u8);
		*len += sizeof(u8);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.beacon.head_len), sizeof(size_t));
		s_tmp += sizeof(size_t);
		*len += sizeof(size_t);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.beacon.tail_len), sizeof(size_t));
		s_tmp += sizeof(size_t);
		*len += sizeof(size_t);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.beacon.beacon_ies_len), sizeof(size_t));
		s_tmp += sizeof(size_t);
		*len += sizeof(size_t);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.beacon.proberesp_ies_len), sizeof(size_t));
		s_tmp += sizeof(size_t);
		*len += sizeof(size_t);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.beacon.assocresp_ies_len), sizeof(size_t));
		s_tmp += sizeof(size_t);
		*len += sizeof(size_t);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.beacon.probe_resp_len), sizeof(size_t));
		s_tmp += sizeof(size_t);
		*len += sizeof(size_t);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.beacon.lci_len), sizeof(size_t));
		s_tmp += sizeof(size_t);
		*len += sizeof(size_t);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.beacon.civicloc_len), sizeof(size_t));
		s_tmp += sizeof(size_t);
		*len += sizeof(size_t);

		memcpy(s_tmp, spec->u.cfg80211.u.start_ap.ap_params.beacon.head, spec->u.cfg80211.u.start_ap.ap_params.beacon.head_len);
		s_tmp += spec->u.cfg80211.u.start_ap.ap_params.beacon.head_len;
		*len += spec->u.cfg80211.u.start_ap.ap_params.beacon.head_len;

		memcpy(s_tmp, spec->u.cfg80211.u.start_ap.ap_params.beacon.tail, spec->u.cfg80211.u.start_ap.ap_params.beacon.tail_len);
		s_tmp += spec->u.cfg80211.u.start_ap.ap_params.beacon.tail_len;
		*len += spec->u.cfg80211.u.start_ap.ap_params.beacon.tail_len;

		memcpy(s_tmp, spec->u.cfg80211.u.start_ap.ap_params.beacon.beacon_ies, spec->u.cfg80211.u.start_ap.ap_params.beacon.beacon_ies_len);
		s_tmp += spec->u.cfg80211.u.start_ap.ap_params.beacon.beacon_ies_len;
		*len += spec->u.cfg80211.u.start_ap.ap_params.beacon.beacon_ies_len;

		memcpy(s_tmp, spec->u.cfg80211.u.start_ap.ap_params.beacon.proberesp_ies, spec->u.cfg80211.u.start_ap.ap_params.beacon.proberesp_ies_len);
		s_tmp += spec->u.cfg80211.u.start_ap.ap_params.beacon.proberesp_ies_len;
		*len += spec->u.cfg80211.u.start_ap.ap_params.beacon.proberesp_ies_len;

		memcpy(s_tmp, spec->u.cfg80211.u.start_ap.ap_params.beacon.assocresp_ies, spec->u.cfg80211.u.start_ap.ap_params.beacon.assocresp_ies_len);
		s_tmp += spec->u.cfg80211.u.start_ap.ap_params.beacon.assocresp_ies_len;
		*len += spec->u.cfg80211.u.start_ap.ap_params.beacon.assocresp_ies_len;

		memcpy(s_tmp, spec->u.cfg80211.u.start_ap.ap_params.beacon.probe_resp, spec->u.cfg80211.u.start_ap.ap_params.beacon.probe_resp_len);
		s_tmp += spec->u.cfg80211.u.start_ap.ap_params.beacon.probe_resp_len;
		*len += spec->u.cfg80211.u.start_ap.ap_params.beacon.probe_resp_len;

		memcpy(s_tmp, spec->u.cfg80211.u.start_ap.ap_params.beacon.lci, spec->u.cfg80211.u.start_ap.ap_params.beacon.lci_len);
		s_tmp += spec->u.cfg80211.u.start_ap.ap_params.beacon.lci_len;
		*len += spec->u.cfg80211.u.start_ap.ap_params.beacon.lci_len;

		memcpy(s_tmp, spec->u.cfg80211.u.start_ap.ap_params.beacon.civicloc, spec->u.cfg80211.u.start_ap.ap_params.beacon.civicloc_len);
		s_tmp += spec->u.cfg80211.u.start_ap.ap_params.beacon.civicloc_len;
		*len += spec->u.cfg80211.u.start_ap.ap_params.beacon.civicloc_len;

		memcpy(s_tmp, &spec->u.cfg80211.u.start_ap.ap_params.beacon_interval, 2*sizeof(int));
		s_tmp += 2*sizeof(int);
		*len += 2*sizeof(int);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.ssid_len), sizeof(size_t));
		s_tmp += sizeof(size_t);
		*len += sizeof(size_t);

		memcpy(s_tmp, spec->u.cfg80211.u.start_ap.ap_params.ssid, spec->u.cfg80211.u.start_ap.ap_params.ssid_len);
		s_tmp += spec->u.cfg80211.u.start_ap.ap_params.ssid_len;
		*len += spec->u.cfg80211.u.start_ap.ap_params.ssid_len;

		memcpy(s_tmp, &spec->u.cfg80211.u.start_ap.ap_params.hidden_ssid, sizeof(enum nl80211_hidden_ssid));
		s_tmp += sizeof(enum nl80211_hidden_ssid);
		*len += sizeof(enum nl80211_hidden_ssid);

		fill_cfg80211_crypto(s_tmp, len, spec);
		fill_cfg80211_acl_data(s_tmp,len, spec);

		memcpy(s_tmp, &spec->u.cfg80211.u.start_ap.ap_params.privacy, sizeof(bool));
		s_tmp += sizeof(bool);
		*len += sizeof(bool);

		memcpy(s_tmp, &spec->u.cfg80211.u.start_ap.ap_params.auth_type, sizeof(enum nl80211_auth_type));
		s_tmp += sizeof(enum nl80211_auth_type);
		*len += sizeof(enum nl80211_auth_type);

		memcpy(s_tmp, &spec->u.cfg80211.u.start_ap.ap_params.smps_mode, sizeof(enum nl80211_smps_mode));
		s_tmp += sizeof(enum nl80211_smps_mode);
		*len += sizeof(enum nl80211_smps_mode);

		memcpy(s_tmp, &spec->u.cfg80211.u.start_ap.ap_params.inactivity_timeout, sizeof(int));
		s_tmp += sizeof(int);
		*len += sizeof(int);

		memcpy(s_tmp, &spec->u.cfg80211.u.start_ap.ap_params.p2p_ctwindow, sizeof(u8));
		s_tmp += sizeof(u8);
		*len += sizeof(u8);

		memcpy(s_tmp, &spec->u.cfg80211.u.start_ap.ap_params.p2p_opp_ps, sizeof(bool));
		s_tmp += sizeof(bool);
		*len += sizeof(bool);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.pbss), sizeof(bool));
		s_tmp += sizeof(bool);
		*len += sizeof(bool);

		memcpy(s_tmp, &(spec->u.cfg80211.u.start_ap.ap_params.beacon_rate), sizeof(struct cfg80211_bitrate_mask));
		s_tmp += sizeof(struct cfg80211_bitrate_mask);
		*len += sizeof(struct cfg80211_bitrate_mask);

		if (spec->u.cfg80211.u.start_ap.ap_params.ht_cap) {
			memcpy(s_tmp, spec->u.cfg80211.u.start_ap.ap_params.ht_cap, sizeof(struct ieee80211_ht_cap));
		}
		s_tmp += sizeof(struct ieee80211_ht_cap);
		*len += sizeof(struct ieee80211_ht_cap);

		if (spec->u.cfg80211.u.start_ap.ap_params.vht_cap) {
			memcpy(s_tmp, spec->u.cfg80211.u.start_ap.ap_params.vht_cap, sizeof(struct ieee80211_vht_cap));
		}
		s_tmp += sizeof(struct ieee80211_vht_cap);
		*len += sizeof(struct ieee80211_vht_cap);

		if (spec->u.cfg80211.u.start_ap.ap_params.he_cap) {
			memcpy(s_tmp, spec->u.cfg80211.u.start_ap.ap_params.he_cap, sizeof(struct ieee80211_he_cap_elem));
		}
		s_tmp += sizeof(struct ieee80211_he_cap_elem);
		*len += sizeof(struct ieee80211_he_cap_elem);

		memcpy(s_tmp, &spec->u.cfg80211.u.start_ap.ap_params.ht_required, 2*sizeof(bool));
		s_tmp += 2*sizeof(bool);
		*len += 2*sizeof(bool);

		return;
}

void handle_cfg80211_msg(wlan_emu_msg_data_t *spec, ssize_t *len, u8 *s_tmp)
{
	if ((spec == NULL) || (s_tmp == NULL) || (len == NULL)) {
		printk(KERN_INFO "%s:%d: NULL Pointer spec : %p s_tmp : %s len : %p \n", __func__, __LINE__, spec, s_tmp, len);
		return;
	}

	switch(spec->u.cfg80211.ops) {
		case wlan_emu_cfg80211_ops_type_start_ap:
			handle_cfg80211_msg_start_ap(spec, len, s_tmp);
			break;
		default:
			break;
	}

	return;
}

 void handle_emu80211_msg_tctrl(wlan_emu_msg_data_t *spec, ssize_t *len, u8 *s_tmp)
 {
	 if ((spec == NULL) || (s_tmp == NULL) || (len == NULL)) {
		 printk(KERN_INFO "%s:%d: NULL Pointer spec : %p s_tmp : %s len : %p \n",
				 __func__, __LINE__, spec, s_tmp, len);
		 return;
	 }
	 memcpy(s_tmp, &spec->type, sizeof(wlan_emu_msg_type_t));
	 s_tmp += sizeof(wlan_emu_msg_type_t);
	 *len += sizeof(wlan_emu_msg_type_t);

	 memcpy(s_tmp, &spec->u.emu80211.ops, sizeof(wlan_emu_emu80211_ops_type_t));
	 s_tmp += sizeof(wlan_emu_emu80211_ops_type_t);
	 *len += sizeof(wlan_emu_emu80211_ops_type_t);

	 memcpy(s_tmp, &spec->u.emu80211.u.ctrl.ctrl, sizeof(wlan_emu_emu80211_ctrl_type_t));
	 s_tmp += sizeof(wlan_emu_emu80211_ctrl_type_t);
	 *len += sizeof(wlan_emu_emu80211_ctrl_type_t);

	 memcpy(s_tmp, &spec->u.emu80211.u.ctrl.coverage, sizeof(wlan_emu_test_coverage_t));
	 s_tmp += sizeof(wlan_emu_test_coverage_t);
	 *len += sizeof(wlan_emu_test_coverage_t);

	 memcpy(s_tmp, &spec->u.emu80211.u.ctrl.type, sizeof(wlan_emu_test_type_t));
	 s_tmp += sizeof(wlan_emu_test_type_t);
	 *len += sizeof(wlan_emu_test_type_t);

	 return;
 }

void handle_emu80211_msg_close(wlan_emu_msg_data_t *spec, ssize_t *len, u8 *s_tmp)
{
	if ((spec == NULL) || (s_tmp == NULL)) {
		printk(KERN_INFO "%s:%d: NULL Pointer \n", __func__, __LINE__);
		return;
	}

	memcpy(s_tmp, &spec->type, sizeof(wlan_emu_msg_type_t));
	s_tmp += sizeof(wlan_emu_msg_type_t);
	*len += sizeof(wlan_emu_msg_type_t);

	memcpy(s_tmp, &spec->u.emu80211.ops, sizeof(wlan_emu_emu80211_ops_type_t));
	s_tmp += sizeof(wlan_emu_emu80211_ops_type_t);
	*len += sizeof(wlan_emu_emu80211_ops_type_t);

	memcpy(s_tmp, &spec->u.emu80211.u.close.fd, sizeof(int));
	s_tmp += sizeof(int);
	*len += sizeof(int);

	return;
}


void handle_emu80211_msg(wlan_emu_msg_data_t *spec, ssize_t *len, u8 *s_tmp)
{
	if ((spec == NULL) || (s_tmp == NULL) || (len == NULL)) {
		printk(KERN_INFO "%s:%d: NULL Pointer spec : %p s_tmp : %s len : %p \n", __func__, __LINE__, spec, s_tmp, len);
		return;
	}

	switch(spec->u.emu80211.ops) {
		case wlan_emu_emu80211_ops_type_tctrl:
			handle_emu80211_msg_tctrl(spec, len, s_tmp);
		break;
		case wlan_emu_emu80211_ops_type_close:
			handle_emu80211_msg_close(spec, len, s_tmp);
		break;
		default:
		break;
	}

	return;
}


void handle_webconfig_msg(wlan_emu_msg_data_t *spec, ssize_t *len, u8 *s_tmp)
{
	if ((spec == NULL) || (s_tmp == NULL) || (len == NULL)) {
		printk(KERN_INFO "%s:%d: NULL Pointer spec : %p s_tmp : %s len : %p \n", __func__, __LINE__, spec, s_tmp, len);
		return;
	}

	memcpy(s_tmp, &spec->type, sizeof(wlan_emu_msg_type_t));
	s_tmp += sizeof(wlan_emu_msg_type_t);
	*len += sizeof(wlan_emu_msg_type_t);

	memcpy(s_tmp, &spec->u.ow_webconfig.subdoc_type, sizeof(webconfig_subdoc_type_t));
	s_tmp += sizeof(webconfig_subdoc_type_t);
	*len += sizeof(webconfig_subdoc_type_t);

    return;
}

static void handle_frame(wlan_emu_msg_data_t *spec, ssize_t *len, u8 *s_tmp)
{
	memcpy(s_tmp, &spec->type, sizeof(wlan_emu_msg_type_t));
	s_tmp += sizeof(wlan_emu_msg_type_t);
	*len += sizeof(wlan_emu_msg_type_t);

	memcpy(s_tmp, &spec->u.frm80211.ops, sizeof(wlan_emu_frm80211_ops_type_t));
	s_tmp += sizeof(wlan_emu_frm80211_ops_type_t);
	*len += sizeof(wlan_emu_frm80211_ops_type_t);

	printk("%s:%d Frame len is %d ops is %d\n", __func__, __LINE__, spec->u.frm80211.u.frame.frame_len, spec->u.frm80211.ops);
	memcpy(s_tmp, &spec->u.frm80211.u.frame.frame_len, sizeof(unsigned int));
	s_tmp += sizeof(unsigned int);
	*len += sizeof(unsigned int);

	memcpy(s_tmp, spec->u.frm80211.u.frame.frame, spec->u.frm80211.u.frame.frame_len);
	s_tmp += spec->u.frm80211.u.frame.frame_len;
	*len += spec->u.frm80211.u.frame.frame_len;

	memcpy(s_tmp, spec->u.frm80211.u.frame.macaddr, ETH_ALEN);
	s_tmp += ETH_ALEN;
	*len += ETH_ALEN;

	memcpy(s_tmp, spec->u.frm80211.u.frame.client_macaddr, ETH_ALEN);
	*len += ETH_ALEN;

	return;
}

static void handle_frm80211_msg(wlan_emu_msg_data_t *spec, ssize_t *len, u8 *s_tmp)
{
	if ((spec == NULL) || (s_tmp == NULL) || (len == NULL)) {
		printk(KERN_INFO "%s:%d: NULL Pointer spec : %p s_tmp : %s len : %p \n", __func__, __LINE__, spec, s_tmp, len);
		return;
	}

	switch(spec->u.frm80211.ops) {
		case wlan_emu_frm80211_ops_type_prb_req:
		case wlan_emu_frm80211_ops_type_prb_resp:
		case wlan_emu_frm80211_ops_type_assoc_resp:
		case wlan_emu_frm80211_ops_type_assoc_req:
		case wlan_emu_frm80211_ops_type_auth:
		case wlan_emu_frm80211_ops_type_deauth:
		case wlan_emu_frm80211_ops_type_disassoc:
		case wlan_emu_frm80211_ops_type_eapol:
		case wlan_emu_frm80211_ops_type_reassoc_req:
		case wlan_emu_frm80211_ops_type_reassoc_resp:
		case wlan_emu_frm80211_ops_type_action:
			handle_frame(spec, len, s_tmp);
			break;
		default:
			printk(KERN_INFO "%s:%d: Not Handling op type %d\n", __func__, __LINE__, spec->u.emu80211.ops);
			break;
	}

	return;
}

static ssize_t rdkfmac_read(struct file *file, char __user *user_buffer,
		size_t size, loff_t *offset)
{
	wlan_emu_msg_data_t *spec;
	ssize_t return_len = 0;
	char *send_buff;
	u8 *s_tmp;

	spec = pop_from_char_device();
	if (spec == NULL) {
		return 0;
	}
	send_buff = kmalloc(size, GFP_KERNEL);
	memset(send_buff, 0, size);
	s_tmp = send_buff;

	switch (spec->type) {
		case wlan_emu_msg_type_cfg80211:
			handle_cfg80211_msg(spec, &return_len, s_tmp);
		break;
		case wlan_emu_msg_type_emu80211:
			handle_emu80211_msg(spec, &return_len, s_tmp);
		break;
		case wlan_emu_msg_type_frm80211:
			handle_frm80211_msg(spec, &return_len, s_tmp);
			break;
		case wlan_emu_msg_type_webconfig:
			handle_webconfig_msg(spec, &return_len, s_tmp);
			break;
		default:
			break;
	}

	if (copy_to_user(user_buffer, send_buff, return_len)) {
		printk("%s: copy_to_user failed\n", __func__);
		return -EFAULT;
	}

	if (spec->type == wlan_emu_msg_type_frm80211) {
		kfree(spec->u.frm80211.u.frame.frame);
	}


	kfree(spec);
	kfree(send_buff);

	return return_len;
}

static int rdkfmac_open(struct inode *inode, struct file *file)
{

	g_char_device.num_inst++;
	printk(KERN_INFO "%s:%d Opened Instances: %d\n", __func__, __LINE__, g_char_device.num_inst);

	return 0;
}

static int rdkfmac_release(struct inode *inode, struct file *file)
{
	if (g_char_device.num_inst > 0) {
		g_char_device.num_inst--;
	}

		printk(KERN_INFO "%s:%d Opened Instances: %d\n", __func__, __LINE__, g_char_device.num_inst);
		return 0;
}

const struct file_operations rdkfmac_fops = {
	.owner = THIS_MODULE,
	.open = rdkfmac_open,
	.read = rdkfmac_read,
	.write = rdkfmac_write,
	.release = rdkfmac_release,
	.poll = rdkfmac_poll
};

int init_rdkfmac_cdev(void)
{
	int ret_val;

	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
	ret_val = register_chrdev_region(MKDEV(RDKFMAC_MAJOR, 0), 1, RDKFMAC_DEVICE_DRIVER_NAME);
	if (ret_val != 0) {
			printk(KERN_INFO "%s:%d: register_chrdev_region():failed with error code:%d\n", __func__, __LINE__, ret_val);
		return ret_val;
	}

	memset(&g_char_device, 0, sizeof(rdkfmac_device_data_t));

	cdev_init(&g_char_device.cdev, &rdkfmac_fops);
	cdev_add(&g_char_device.cdev, MKDEV(RDKFMAC_MAJOR, 0), 1);
	g_char_device.class = class_create(THIS_MODULE, RDKFMAC_CLASS_NAME);
	if (IS_ERR(g_char_device.class)){
		printk(KERN_ALERT "cdrv : register device class failed\n");
		return PTR_ERR(g_char_device.class);
	}

	INIT_LIST_HEAD(&g_char_device.list_head);
	g_char_device.list_tail = &g_char_device.list_head;
	printk(KERN_INFO "%s:%d: registered successfully\n", __func__, __LINE__);
	g_char_device.tdev = MKDEV(RDKFMAC_MAJOR, 0);
	g_char_device.dev = device_create(g_char_device.class, NULL,
				g_char_device.tdev, NULL, RDKFMAC_DEVICE_NAME);

	return 0;
}

void cleanup_rdkfmac_cdev(void)
{
	device_destroy(g_char_device.class, g_char_device.tdev);
	class_destroy(g_char_device.class);
	cdev_del(&g_char_device.cdev);
	unregister_chrdev_region(MKDEV(RDKFMAC_MAJOR, 0), 1);

	printk(KERN_INFO "%s:%d: unregistered successfully\n", __func__, __LINE__);
}

unsigned int get_list_entries_count_in_char_device(void)
{
	unsigned count = 0;
	struct list_head *ptr = &g_char_device.list_head;

	for (ptr = &g_char_device.list_head; ptr != g_char_device.list_tail; ptr = ptr->next) {
		count++;
	}

	return count;
}

wlan_emu_msg_data_t*pop_from_char_device(void)
{
	wlan_emu_msg_data_t *spec = NULL;
	wlan_emu_msg_data_entry_t *entry = NULL;

	if (g_char_device.list_tail == &g_char_device.list_head) {
		printk("%s:%d list is empty\n", __func__, __LINE__);
		return NULL;
	}

	entry = list_entry(g_char_device.list_tail, wlan_emu_msg_data_entry_t, list_entry);

	g_char_device.list_tail= g_char_device.list_tail->prev;
	list_del(&entry->list_entry);

	spec = entry->spec;
	kfree(entry);

	return spec;
}

struct rdkfmac_device_data *get_char_device_data(void)
{
	return &g_char_device;
}

