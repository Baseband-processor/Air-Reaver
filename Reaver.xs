
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "C/src/wps/wps.h"
#include "C/src/wps/wps_i.h"
#include "C/src/wps/wps_dev_attr.h"
#include "C/src/libwps/libwps.h"
#include "C/src/common/wpa_common.h"
#include "C/src/pins.h"
#include "C/src/send.h"
#include "C/src/pixie.h"
#include "C/src/cracker.h"
#include "C/src/builder.h"
#include "C/src/wps/wps_registrar.c"

typedef struct wps_er                              *WPS_ER;
typedef struct wps_context                         *WPS_CONTEXT;
typedef struct wps_credential                      *WPS_CREDENTIAL;

typedef struct {
	u8 mac_addr[ETH_ALEN];
	char *device_name;
	char *manufacturer;
	char *model_name;
	char *model_number;
	char *serial_number;
	u8 pri_dev_type[WPS_DEV_TYPE_LEN];
	u32 os_version;
	u8 rf_bands;
}wps_device_data;	
		
typedef struct wps_device_data                    *WPS_DEVICE_DATA;

typedef struct {
	int proto
	int pairwise_cipher
	int group_cipher
	int key_mgmt
	int capabilities
	size_t num_pmkid
	const u8 *pmkid
	int mgmt_group_cipher
}wpa_ie_data;

typedef struct wpa_ie_data		            *WPA_IE_DATA;

typedef struct{
	le16 algorithm;
	le16 sequence;
	le16 status;
}authentication_management_frame;

typedef struct authentication_management_frame       *AUTH_MANAGEMENT_FRAME;

typedef struct {
	le16 capability;
	le16 listen_interval;
}association_request_management_frame;

typedef struct association_request_management_frame  *ASSOCIATION_REQUEST_MANAGEMENT_FRAME;

typedef struct {
	le16 capability;
	le16 status;
	le16 id;
}association_response_management_frame;

typedef struct association_response_management_frame  *ASSOCIATION_RESP_MANAGEMENT_FRAME;
	
typedef struct  {
	unsigned char timestamp[TIMESTAMP_LEN];
	le16 beacon_interval;
	le16 capability;
}beacon_management_frame;

typedef struct beacon_management_frame               *BEACON_MANAGEMENT_FRAME;

typedef struct {
	struct wps_registrar_device *next;
	struct wps_device_data dev;
	u8 uuid[WPS_UUID_LEN];
}wps_registrar_device;

typedef struct wps_registrar_device                  *WPS_REGISTRAR_DEVICE;
typedef struct wpa_buf                               *WPA_BUF;
typedef struct wps_context                           *WPS_CONTEXT;
typedef struct dl_list                               *DLLIST;
typedef struct wps_pbc_session                       *WPS_PBC_SESSION;

typedef struct  {
	WPS_CONTEXT *wps;
	int pbc;
	int selected_registrar;
	int (*new_psk_cb)(void *ctx, const u8 *mac_addr, const u8 *psk, size_t psk_len);
	int (*set_ie_cb)(void *ctx, WPA_BUF *beacon_ie, WPA_BUF *probe_resp_ie);
	void (*pin_needed_cb)(void *ctx, const u8 *uuid_e, const WPS_DEVICE_DATA *dev);
	void (*reg_success_cb)(void *ctx, const u8 *mac_addr, const u8 *uuid_e);
	void (*set_sel_reg_cb)(void *ctx, int sel_reg, u16 dev_passwd_id, u16 sel_reg_config_methods);
	void (*enrollee_seen_cb)(void *ctx, const u8 *addr, const u8 *uuid_e, const u8 *pri_dev_type, u16 config_methods, u16 dev_password_id, u8 request_type, const char *dev_name);
	void *cb_ctx;
	DLLIST pins;
	WPS_PBC_SESSION *pbc_sessions;
	int skip_cred_build;
	WPA_BUF *extra_cred;
	int disable_auto_conf;
	int sel_reg_union;
	int sel_reg_dev_password_id_override;
	int sel_reg_config_methods_override;
	int static_wep_only;
	WPS_REGISTRAR_DEVICE *devices;
	int force_pbc_overlap;
}wps_registrar;

typedef struct wps_registrar                         *WPS_REGISTRAR;


typedef struct  {
	WPS_CONTEXT *wps;
	char *key;
	char *essid;
	int registrar;
	int er;
	enum {
		SEND_M1, RECV_M2, SEND_M3, RECV_M4, SEND_M5, RECV_M6, SEND_M7,
		RECV_M8, RECEIVED_M2D, WPS_MSG_DONE, RECV_ACK, WPS_FINISHED,
		SEND_WSC_NACK,
		RECV_M1, SEND_M2, RECV_M3, SEND_M4, RECV_M5, SEND_M6,
		RECV_M7, SEND_M8, RECV_DONE, SEND_M2D, RECV_M2D_ACK
	} state;
	u8 uuid_e[WPS_UUID_LEN];
	u8 uuid_r[WPS_UUID_LEN];
	u8 mac_addr_e[ETH_ALEN];
	u8 nonce_e[WPS_NONCE_LEN];
	u8 nonce_r[WPS_NONCE_LEN];
	u8 psk1[WPS_PSK_LEN];
	u8 psk2[WPS_PSK_LEN];
	u8 snonce[2 * WPS_SECRET_NONCE_LEN];
	u8 peer_hash1[WPS_HASH_LEN];
	u8 peer_hash2[WPS_HASH_LEN];
	WPA_BUF *dh_privkey;
	WPA_BUF *dh_pubkey_e;
	WPA_BUF *dh_pubkey_r;
	u8 authkey[WPS_AUTHKEY_LEN];
	u8 keywrapkey[WPS_KEYWRAPKEY_LEN];
	u8 emsk[WPS_EMSK_LEN];
	WPA_BUF *last_msg;
	u8 *dev_password;
	size_t dev_password_len;
	u16 dev_pw_id;
	int pbc;
	u8 request_type;
	u16 encr_type;
	u16 auth_type;
	u8 *new_psk;
	size_t new_psk_len;
	int wps_pin_revealed;
	WPS_CREDENTIAL cred;
	WPS_DEVICE_DATA peer_dev;
	u16 config_error;
	int ext_reg;
	int int_reg;
	WPS_CREDENTIAL *new_ap_settings;
	void *dh_ctx;
	void (*ap_settings_cb)(void *ctx, const WPS_CREDENTIAL *cred);
	void *ap_settings_cb_ctx;
	WPS_CREDENTIAL *use_cred;
	int use_psk_key;
}wps_data;

typedef struct wps_data                              *WPS_DATA;

typedef struct wps_registrar_config                  *WPS_REGISTRAR_CONFIG;
typedef struct wps_parse_attr                        *WPS_PARSE_ATTR;
typedef time_t TIME;

size_t
build_radio_tap_header(rt_header)
	void *rt_header

size_t
build_association_management_frame(f)
	ASSOCIATION_REQUEST_MANAGEMENT_FRAME *f

size_t
build_AUTH_MANAGEMENT_FRAME(f)
	AUTH_MANAGEMENT_FRAME *f

#size_t
# build_ssid_tagged_parameter(unsigned char buf[IW_ESSID_MAX_SIZE+2], char *essid)

size_t
build_supported_rates_tagged_parameter(buf, buflength)
	unsigned char *buf
	size_t buflength

#size_t
#build_wps_tagged_parameter(unsigned char buf[2+WPS_TAG_SIZE])

size_t
build_htcaps_parameter(buf, buflength)
	unsigned char *buf
	size_t buflength

void*
build_wps_probe_request(bssid,essid, length)
	unsigned char *bssid
	char *essid
	size_t *length

void *
build_snap_packet(length)
	size_t *length

void *
build_dot1X_header(type, payload_len, length)
	uint8_t type
	uint16_t payload_len
	size_t *length

void *
build_eap_header(id, code, type, payload_len, length)
	uint8_t id
	uint8_t code
	uint8_t type
	uint16_t payload_len
	size_t *length
	
void *
build_eapol_start_packet(length)
	size_t *length
	
void *
build_eap_packet(payload, payload_length, length)
	const void *payload
	uint16_t payload_length
	size_t *length
	
void *
build_eap_failure_packet(length)
	size_t *length
void
crack()
	
void
advance_pin_count()

void
display_status(pin_count, start_time)
	float pin_count
	TIME_T start_time
void
pixie_format(key, length, outbuf)
	const unsigned char *key
	unsigned length
	char *outbuf

void
pixie_attack(void)


char * 
build_wps_pin()

char *
build_next_pin()

void
generate_pins()

int
send_eapol_start()

int
send_identity_response()

int
send_msg(type)
	int type
void
send_termination()

void
send_wsc_nack()

int
resend_last_packet(void)
	void void
int
send_packet_internal(callerfunc, file, callerline, packet, length, use_timer)
	const char* callerfunc
	const char* file
	int callerline
	const void *packet
	size_t length
	int use_timer

WPS_REGISTRAR *
wps_registrar_init(wps, cfg)
	WPS_CONTEXT *wps
	const WPS_REGISTRAR_CONFIG *cfg
void
wps_registrar_deinit(reg)
	WPS_REGISTRAR *reg
int
wps_registrar_add_pin(reg, uuid, pin, pin_len, timeout)
	WPS_REGISTRAR  *reg
	const u8 *uuid
	const u8 *pin
	size_t pin_len
	int timeout
int
wps_registrar_invalidate_pin(reg, uuid)
	WPS_REGISTRAR *reg
	const u8 *uuid
int
wps_registrar_unlock_pin(reg, uuid)
	WPS_REGISTRAR *reg
	const u8 *uuid
int
wps_registrar_button_pushed(reg)
	WPS_REGISTRAR *reg
	
void
wps_registrar_probe_req_rx(reg,addr, wps_data)
	WPS_REGISTRAR *reg
	const u8 *addr
	WPA_BUF *wps_data
int
wps_registrar_update_ie(reg)
	WPS_REGISTRAR *reg
	
int
wps_registrar_get_info(reg, addr, buf, buflen)
	WPS_REGISTRAR  *reg
	const u8 *addr
	char *buf
	size_t buflen
	  CODE:
	     RETVAL = wps_registrar_get_info(&reg, &addr, &buf, buflen);
	  OUTPUT:
	     RETVAL
	     
unsigned int 
wps_pin_checksum(pin)
	unsigned int pin
	
unsigned int 
wps_pin_valid(pin)
	unsigned int pin
	
unsigned int 
wps_generate_pin(void)

void
wps_free_pending_msgs(struct upnp_pending_message *msgs)

struct oob_device_data *
wps_get_oob_device(char *device_type)

struct oob_nfc_device_data *
wps_get_oob_nfc_device(char *device_name)

int
 wps_get_oob_method(method)
	char *method
	
int
wps_attr_text(data, buf, end)
	WPA_BUF *data
	char *buf
	char *end
	
WPS_ER *
wps_er_init(wps, ifname)
	WPS_CONTEXT *wps
	const char *ifname
void
wps_er_refresh(er)
	WPS_ER *er
void
wps_er_set_sel_reg(er,  sel_reg,  dev_passwd_id, sel_reg_config_methods)
	WPS_ER *er
	int sel_reg
	u16 dev_passwd_id
	u16 sel_reg_config_methods
	CODE:
		RETVAL = wps_er_set_sel_reg(&er,  sel_reg,  dev_passwd_id, sel_reg_config_methods);
	  OUTPUT:
	        RETVAL
	
void
wps_kdf(key, label_prefix, label_prefix_len, label, res, res_len)
	const u8 *key
	const u8 *label_prefix
	size_t label_prefix_len
	const char *label
	u8 *res
	size_t res_len
	  CODE:
		RETVAL = wps_kdf(&key, &label_prefix, label_prefix_len, &label, &res, res_len);
	  OUTPUT:
	        RETVAL
int
wps_derive_keys(wps)
	WPS_DATA *wps

void
wps_derive_psk(wps, dev_passwd, dev_passwd_len)
	WPS_DATA *wps
	const u8 *dev_passwd
	size_t dev_passwd_len
	
WPA_BUF *
wps_decrypt_encr_settings(wps, encr, encr_len)
	WPS_DATA *wps
	const u8 *encr
	size_t encr_len
void
wps_success_event(wps)
	WPS_CONTEXT *wps

void
wps_pwd_auth_fail_event(wps, enrollee,  part)
	WPS_CONTEXT *wps
	int enrollee
	int part
	
void
wps_pbc_overlap_event(wps)
	WPS_CONTEXT *wps
void
wps_pbc_timeout_event(wps)
	WPS_CONTEXT *wps
	
int
wps_parse_msg(msg, attr)
	const WPABUF *msg
	WPS_PARSE_ATTR *attr
	
	

int
wps_build_public_key(WPS_DATA *wps, WPA_BUF *msg)

int
wps_build_req_type(struct wpabuf *msg, enum wps_request_type type)

int
wps_build_resp_type(struct wpabuf *msg, enum wps_response_type type)

int
wps_build_config_methods(struct wpabuf *msg, u16 methods)
			
int
wps_build_uuid_e(struct wpabuf *msg, const u8 *uuid)
int
wps_build_dev_password_id(struct wpabuf *msg, u16 id)
int
wps_build_config_error(struct wpabuf *msg, u16 err)
int
wps_build_authenticator(struct wps_data *wps, struct wpabuf *msg)
int
wps_build_key_wrap_auth(struct wps_data *wps, struct wpabuf *msg)
int
wps_build_encr_settings(struct wps_data *wps, struct wpabuf *msg,
			    struct wpabuf *plain)
int
 wps_build_version(struct wpabuf *msg)
int
 wps_build_msg_type(struct wpabuf *msg, enum wps_msg_type msg_type)
int
 wps_build_enrollee_nonce(struct wps_data *wps, struct wpabuf *msg)
int
 wps_build_registrar_nonce(struct wps_data *wps, struct wpabuf *msg)
int
 wps_build_auth_type_flags(struct wps_data *wps, struct wpabuf *msg)
int
 wps_build_encr_type_flags(struct wps_data *wps, struct wpabuf *msg)
int
 wps_build_conn_type_flags(struct wps_data *wps, struct wpabuf *msg)
int
 wps_build_assoc_state(struct wps_data *wps, struct wpabuf *msg)
int
 wps_build_oob_dev_password(struct wpabuf *msg, struct wps_context *wps)

/* wps_attr_process.c */
int
 wps_process_authenticator(struct wps_data *wps, const u8 *authenticator,
			      const struct wpabuf *msg)
int
 wps_process_key_wrap_auth(struct wps_data *wps, struct wpabuf *msg,
			      const u8 *key_wrap_auth)
int
 wps_process_cred(struct wps_parse_attr *attr,
		     struct wps_credential *cred)
int
 wps_process_ap_settings(struct wps_parse_attr *attr,
			    struct wps_credential *cred)

/* wps_enrollee.c */
struct wpabuf * wps_enrollee_get_msg(struct wps_data *wps,
				     enum wsc_op_code *op_code)
enum wps_process_res wps_enrollee_process_msg(struct wps_data *wps,
					      enum wsc_op_code op_code,
					      const struct wpabuf *msg)

/* wps_registrar.c */
struct wpabuf * wps_registrar_get_msg(struct wps_data *wps,
				      enum wsc_op_code *op_code,
				      int type)
enum wps_process_res wps_registrar_process_msg(struct wps_data *wps,
					       enum wsc_op_code op_code,
					       const struct wpabuf *msg)
int
wps_build_cred(struct wps_data *wps, struct wpabuf *msg)

int
wps_device_store(struct wps_registrar *reg,struct wps_device_data *dev, const u8 *uuid)

void
wps_registrar_selected_registrar_changed(struct wps_registrar *reg)
	
int
wps_er_pbc(struct wps_er *er, const u8 *uuid)

int
wps_er_learn(struct wps_er *er, const u8 *uuid, const u8 *pin,
		 size_t pin_len)

int
 wps_dev_type_str2bin(const char *str, u8 dev_type[WPS_DEV_TYPE_LEN])
char
 * wps_dev_type_bin2str(const u8 dev_type[WPS_DEV_TYPE_LEN], char *buf,
			    size_t buf_len)
void
uuid_gen_mac_addr(const u8 *mac_addr, u8 *uuid)

u16 
wps_config_methods_str2bin(const char *str)


int
 wps_build_device_attrs(struct wps_device_data *dev, struct wpabuf *msg)
int
 wps_build_os_version(struct wps_device_data *dev, struct wpabuf *msg)
int
 wps_build_rf_bands(struct wps_device_data *dev, struct wpabuf *msg)
int
 wps_build_primary_dev_type(struct wps_device_data *dev,
			       struct wpabuf *msg)
int
 wps_process_device_attrs(struct wps_device_data *dev,
			     struct wps_parse_attr *attr)
int
wps_process_os_version(struct wps_device_data *dev, const u8 *ver)
	
int
wps_process_rf_bands(struct wps_device_data *dev, const u8 *bands)

void
wps_device_data_dup(struct wps_device_data *dst,
			 const struct wps_device_data *src)
void
wps_device_data_free(struct wps_device_data *dev)

int
parse_wps_tag(const u_char *tags, size_t len, struct libwps_data *wps)

unsigned char *
get_wps_data(const u_char *data, size_t len, size_t *tag_len)

unsigned char *
get_wps_data_element(const u_char *data, size_t len, uint16_t type, size_t *el_len)


int
libwps_has_rt_header(const u_char *packet, size_t len)

const u_char *
libwps_radio_header(packet, length)
	const u_char *packet
	size_t length
int
wpa_eapol_key_mic(const u8 *key, int ver, const u8 *buf, size_t len, u8 *mic)
	
void
wpa_pmk_to_ptk(const u8 *pmk, size_t pmk_len, const char *label,
		    const u8 *addr1, const u8 *addr2,
		    const u8 *nonce1, const u8 *nonce2,
		    u8 *ptk, size_t ptk_len, int use_sha256)

int
wpa_ft_mic(const u8 *kck, const u8 *sta_addr, const u8 *ap_addr, u8 transaction_seqnum, const u8 *mdie, size_t mdie_len, const u8 *ftie, size_t ftie_len, const u8 *rsnie, size_t rsnie_len, const u8 *ric, size_t ric_len, u8 *mic)
void
wpa_derive_pmk_r0(const u8 *xxkey, size_t xxkey_len,    const u8 *ssid, size_t ssid_len, const u8 *mdid, const u8 *r0kh_id, size_t r0kh_id_len, const u8 *s0kh_id, u8 *pmk_r0, u8 *pmk_r0_name)
void
wpa_derive_pmk_r1_name(const u8 *pmk_r0_name, const u8 *r1kh_id, const u8 *s1kh_id, u8 *pmk_r1_name)
void
wpa_derive_pmk_r1(const u8 *pmk_r0, const u8 *pmk_r0_name, const u8 *r1kh_id, const u8 *s1kh_id, u8 *pmk_r1, u8 *pmk_r1_name)
	
void
wpa_pmk_r1_to_ptk(const u8 *pmk_r1, const u8 *snonce, const u8 *anonce, const u8 *sta_addr, const u8 *bssid, const u8 *pmk_r1_name, u8 *ptk, size_t ptk_len, u8 *ptk_name)


int
wpa_parse_wpa_ie_rsn(const u8 *rsn_ie, size_t rsn_ie_len, struct wpa_ie_data *data)

void
rsn_pmkid(const u8 *pmk, size_t pmk_len, const u8*aa, const u8 *spa, u8 *pmkid, int use_sha256)

const char * 
wpa_cipher_txt(cipher)
	int cipher
	
const char * 
wpa_key_mgmt_txt(key_management, protocol)
	int key_management
	int protocol
int
wpa_compare_rsn_ie(ft_initial_assoc, ie1, ie1len,ie2, ie2len)
	int ft_initial_assoc
	const u8 *ie1
	size_t ie1len
	const u8 *ie2
	size_t ie2len
	    CODE:
		RETVAL = wpa_compare_rsn_ie(ft_initial_assoc, &ie1, ie1len, &ie2, ie2len);
	   OUTPUT:
		RETVAL
int
wpa_insert_pmkid(ies, ies_len, pmkid)
	u8 *ies
	size_t ies_len
	const u8 *pmkid
	  CODE:
	    RETVAL = wpa_insert_pmkid(&ies, ies_len, &pmkid);
	  OUTPUT:
	     RETVAL
