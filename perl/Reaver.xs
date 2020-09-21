
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define SSID_TAG_NUMBER		0
#define RATES_TAG_NUMBER	1
#define CHANNEL_TAG_NUMBER	3

#define TIMESTAMP_LEN           8
#define MAC_ADDR_LEN    	6
#define LIBWPS_MAX_STR_LEN 256
#define WPS_UUID_LEN 16
#define LISTEN_INTERVAL         0x0064

#define ETH_ALEN 6
#define P1_SIZE			10000
#define P2_SIZE			1000

#define WPA_CIPHER_NONE BIT(0)
#define WPA_CIPHER_WEP40 BIT(1)
#define WPA_CIPHER_WEP104 BIT(2)
#define WPA_CIPHER_TKIP BIT(3)
#define WPA_CIPHER_CCMP BIT(4)
#ifdef CONFIG_IEEE80211W
#define WPA_CIPHER_AES_128_CMAC BIT(5)
#endif /* CONFIG_IEEE80211W */

#define FC_PROBE_REQUEST        0x0040
#define FC_STANDARD		0x0108

#define TAG_SUPPORTED_RATES "\x01\x08\x02\x04\x0b\x16\x0c\x12\x18\x24"
#define TAG_EXT_RATES "\x32\x04\x30\x48\x60\x6c"
#define TAG_HT_CAPS "\x2d\x1a\x72\x01\x13\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define WPS_PROBE_IE      "\xdd\x09\x00\x50\xf2\x04\x10\x4a\x00\x01\x10"
#define ALL_TAGS TAG_SUPPORTED_RATES TAG_EXT_RATES TAG_HT_CAPS WPS_PROBE_IE


#define end_htole16(x) (uint16_t)(x)

#define DOT1X_EAP_PACKET	0x00
#define EAP_IDENTITY 		0x01
#define EAP_EXPANDED            0xFE
#define RADIOTAP_HEADER         "\0\0"

#define EAP_REQUEST  1
#define	EAP_RESPONSE 2
#define	EAP_SUCCESS  3
#define	EAP_FAILURE  4

#define PIXIE_FREE(KEY) \
	do { \
		if(pixie.KEY) free(pixie.KEY); \
		pixie.KEY = 0; \
	} while(0)

#define PIXIE_SET(KEY, VALUE) \
	do { \
		if(pixie.KEY) free(pixie.KEY); \
		pixie.KEY = strdup(VALUE); \
	} while(0)


#include "Ctxs.h"


typedef struct wps_er                              *WPS_ER;
typedef struct wps_context                         *WPS_CONTEXT;
typedef struct wps_credential                      *WPS_CREDENTIAL;
typedef enum wps_msg_type                          WPS_MESSAGE_TYPE;
typedef enum wps_process_res			   WPS_PROCESS_RES;

typedef struct dot11_frame_header                  DOT_11_FRAME_H;

typedef struct {
        uint8_t number;
        uint8_t len;
}tagged_parameter;


typedef struct tagged_parameter TAG_PARAMS;

typedef struct {
        uint8_t version;
        uint8_t state;
        uint8_t locked;
        char manufacturer[LIBWPS_MAX_STR_LEN];
        char model_name[LIBWPS_MAX_STR_LEN];
        char model_number[LIBWPS_MAX_STR_LEN];
        char device_name[LIBWPS_MAX_STR_LEN];
        char ssid[LIBWPS_MAX_STR_LEN];
        char uuid[LIBWPS_MAX_STR_LEN];
        char serial[LIBWPS_MAX_STR_LEN];
        char selected_registrar[LIBWPS_MAX_STR_LEN];
        char response_type[LIBWPS_MAX_STR_LEN];
        char primary_device_type[LIBWPS_MAX_STR_LEN];
        char config_methods[LIBWPS_MAX_STR_LEN];
        char rf_bands[LIBWPS_MAX_STR_LEN];
        char os_version[LIBWPS_MAX_STR_LEN];
}libwps_data;

typedef struct libwps_data                    LIBWPS_DATA;
typedef enum  wsc_op_code 		      WSC_OP_CODE;

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
	
typedef struct wps_device_data WPS_DEVICE_DATA;	

typedef struct {
	int proto;
	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;
	int capabilities;
	size_t num_pmkid;
	const u8 *pmkid;
	int mgmt_group_cipher;
}wpa_ie_data;

typedef struct wpa_ie_data        WPA_IE_DATA;

typedef struct authentication_management_frame{
	le16 algorithm;
	le16 sequence;
	le16 status;
}AUTH_MANAGEMENT_FRAME;


typedef struct association_request_management_frame{
	le16 capability;
	le16 listen_interval;
}ASSOCIATION_REQUEST_MANAGEMENT_FRAME;


typedef struct association_response_management_frame{
	le16 capability;
	le16 status;
	le16 id;
}ASSOCIATION_RESP_MANAGEMENT_FRAME;

	
typedef struct  beacon_management_frame{
	unsigned char timestamp[TIMESTAMP_LEN];
	le16 beacon_interval;
	le16 capability;
}BEACON_MANAGEMENT_FRAME;


typedef struct wps_registrar_device{
	struct wps_registrar_device *next;
	struct wps_device_data dev;
	u8 uuid[WPS_UUID_LEN];
}WPS_REGISTRAR_DEVICE;

typedef struct wpa_buf                               *WPA_BUF;
typedef struct wps_context                           *WPS_CONTEXT;
typedef struct dl_list                               *DLLIST;
typedef struct wps_pbc_session                       *WPS_PBC_SESSION;

typedef struct  wps_registrar{
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
}WPS_REGISTRAR;



typedef struct  wps_data{
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
}WPS_DATA;


typedef struct {
        int last_wps_state;             
        int p1_index;                   
        int p2_index;                   
        char *p1[P1_SIZE];              
        char *p2[P2_SIZE];              
	char *static_p1;			
	char *static_p2;		
	int use_pin_string;		
        enum *key_state key_status;      
	int dh_small;			
	int external_association;	
	int oo_send_nack;
	int win7_compat;
        int delay;                 
        int fail_delay;                
        int recurring_delay;            
	int lock_delay;			
	int ignore_locks;		
        int recurring_delay_count;	
        int eap_terminate;              
        int max_pin_attempts;           
        int rx_timeout;                 
        int timeout_is_nack;            
        int m57_timeout;                
        int out_of_time;                
	unsigned long long resend_timeout_usec;   
        enum *debug_level debug;         
        int eapol_start_count;          
        int fixed_channel;              
	int auto_channel_select;
	int wifi_band;			
	int channel;			
	int repeat_m6;			
	int max_num_probes;		
	int validate_fcs;		
        enum *wsc_op_code opcode;        
        uint8_t eap_id;                
        uint16_t ap_capability;         
        unsigned char bssid[MAC_ADDR_LEN];    
        unsigned char mac[MAC_ADDR_LEN];             
	unsigned char vendor_oui[1+3];	
	unsigned char *htcaps;		
	int htcaps_len;			
	unsigned char *ap_rates;	
	int ap_rates_len;		
	unsigned char *ap_ext_rates;	
	int ap_ext_rates_len;		
	FILE *fp;		
	char *session;			
        char *ssid;                     
        char *iface;                    
        char *pin;                      
	char *exec_string;		
        enum *nack_code nack_reason;     
        pcap_t *handle;                 
	int output_fd;			
	uint64_t uptime;		
        WPS_DATA *wps;           
}globals;

typedef struct globals                               GLOB;
typedef struct wps_registrar_config                  *WPS_REGISTRAR_CONFIG;
typedef struct wps_parse_attr                        *WPS_PARSE_ATTR;
typedef time_t 					     TIME;

MODULE = Air::Reaver   PACKAGE = Air::Reaver
PROTOTYPES: DISABLE

size_t
build_radio_tap_header(rt_header)
	void *rt_header
CODE:
	#define RADIOTAP_HEADER_LENGTH \
	"\x0c\0"
	#define RADIOTAP_HEADER_PRESENT_FLAGS \
	"\x04\x80\0\0" 
	#define RADIOTAP_HEADER_RATE_OPTION \
	"\0\0" 
	#define RADIOTAP_HEADER_LENGTH \
	"\x0a\0" 
	#define RADIOTAP_HEADER_PRESENT_FLAGS \
	"\x00\x80\0\0"
	#define RADIOTAP_HEADER_RATE_OPTION ""
	#define RADIOTAP_HEADER \
	"\0\0"  \
	RADIOTAP_HEADER_LENGTH \
	RADIOTAP_HEADER_PRESENT_FLAGS \
	RADIOTAP_HEADER_RATE_OPTION \
	"\x18\0" 
	memcpy(rt_header, RADIOTAP_HEADER, sizeof(RADIOTAP_HEADER)-1);
	RETVAL = ( sizeof(RADIOTAP_HEADER) - 1 );
OUTPUT:
	RETVAL
	

int 
globule_init()
CODE:
	int ret = 0;
	GLOB *globule;
	globule = malloc(sizeof(GLOB *));
	if(globule)
	{
		memset(globule, 0, sizeof(GLOB *));
		ret = 1;
		# globule->resend_timeout_usec = 200000;
		globule->output_fd = -1;

	}
	return ret;

WPS_DATA *
get_wps()
CODE:
	GLOB *globule;
	return globule->wps;


uint16_t 
get_ap_capability()
CODE:
GLOB * globule;
RETVAL = globule->ap_capability;
OUTPUT:
RETVAL

void 
set_channel(channel)
int channel
CODE:
	GLOB *globule;
	globule->channel = channel;
        return( 0 );

int 
get_channel()
CODE:
	GLOB *globule;
	return globule->channel;

void 
set_bssid(value)
unsigned char *value
CODE:
	GLOB *globule;
	memcpy(globule->bssid, value, MAC_ADDR_LEN);
	return 0;

size_t
build_association_management_frame(f)
         ASSOCIATION_REQUEST_MANAGEMENT_FRAME *f


size_t
build_authentication_management_frame(f)
         AUTH_MANAGEMENT_FRAME *f


size_t
build_htcaps_parameter(buf, buflength)
	unsigned char *buf
	size_t buflength


void*
build_wps_probe_request(bssid, essid, length)
	unsigned char *bssid
	char *essid
	size_t *length
CODE:	
	TAG_PARAMS *ssid_tag;
	void *packet = NULL;
	size_t offset = 0, rt_len = 0, dot11_len = 0, ssid_tag_len = 0, packet_len = 0;
	int broadcast = !memcmp(bssid, "\xff\xff\xff\xff\xff\xff", 6);

	if(!broadcast && essid != NULL)
	{
		 ssid_tag->len = (uint8_t) strlen(essid);
	}
	else
	{
		ssid_tag->len = 0;
	}

	ssid_tag->number = SSID_TAG_NUMBER;
	ssid_tag_len = ssid_tag->len + sizeof(TAG_PARAMS *);
	struct radio_tap_header *rt_header;
	rt_len = build_radio_tap_header(&rt_header);
	DOT_11_FRAME_H *dot11_header;
	dot11_len = build_dot11_frame_header_m(&dot11_header, FC_PROBE_REQUEST, bssid);

	packet_len = rt_len + dot11_len + ssid_tag_len;


void *
build_snap_packet(length)
	size_t *length
CODE:
	void *packet = NULL;
	size_t rt_len = 0, dot11_len = 0, llc_len = 0, packet_len = 0;
	struct radio_tap_header rt_header;
	struct dot11_frame_header dot11_header;
	struct llc_header llc_header;
	rt_len = build_radio_tap_header(&rt_header);
        dot11_len = build_dot11_frame_header(&dot11_header, FC_STANDARD);
        llc_len = build_llc_header(&llc_header);

	packet_len = rt_len + dot11_len + llc_len;
	//packet = malloc(packet_len);
	Newx(packet, packet_len, 1);
	if(packet) {
		//memset((void *) packet, 0, packet_len);
		Zero(packet, 0, packet_len);
		//memcpy((void *) packet, &rt_header, rt_len);
		Copy(&rt_header, packet, rt_len, 1);
		//memcpy((void *) ((char *) packet+rt_len), &dot11_header, dot11_len);
		char *p = packet + rt_len;
		Copy(&dot11_header, p, dot11_len, 1);
		//memcpy((void *) ((char *) packet+rt_len+dot11_len), &llc_header, llc_len);
		char *p1 = packet + rt_len + dot11_len;
		Copy(&llc_header, p1, llc_len, 1);
		*len = packet_len;
	}
	return packet;

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
CODE:
	void *buf = NULL, *snap_packet = NULL, *eap_header = NULL, *dot1x_header = NULL, *wfa_header = NULL;
	size_t buf_len = 0, snap_len = 0, eap_len = 0, dot1x_len = 0, wfa_len = 0, offset = 0, total_payload_len = 0;
	uint8_t eap_type = 0, eap_code = 0;
	WPS_DATA *wps = get_wps();

	switch(wps->state)
	{
		case RECV_M1:
			eap_code = EAP_RESPONSE;
			eap_type = EAP_IDENTITY;
			break;
		default:
			eap_code = EAP_RESPONSE;
			eap_type = EAP_EXPANDED;
	}
	total_payload_len = payload_length;
	if(eap_type == EAP_EXPANDED)
	{
		wfa_header = build_wfa_header(get_opcode(), &wfa_len);
		total_payload_len += wfa_len;
	}

	snap_packet = build_snap_packet(&snap_len);
	eap_header = build_eap_header(get_eap_id(), eap_code, eap_type, total_payload_len, &eap_len);
	dot1x_header = build_dot1X_header(DOT1X_EAP_PACKET, (total_payload_len+eap_len), &dot1x_len);
	if(snap_packet && eap_header && dot1x_header)
	{
		buf_len = snap_len + dot1x_len + eap_len + total_payload_len;
		buf = malloc(buf_len);
		if(buf)
		{
			//memset((void *) buf, 0, buf_len);
			Zero(buf, 1, buf_len);
			//memcpy((void *) buf, snap_packet, snap_len);
			Copy(snap_packet, buf, snap_len, 1);
			offset += snap_len;
			//memcpy((void *) ((char *) buf+offset), dot1x_header, dot1x_len);
			char *boffset =  buf + offset;
			Copy(dot1x_header, boffset, dot1x_len, 1);
			offset += dot1x_len;
			//memcpy((void *) ((char *) buf+offset), eap_header, eap_len);
			Copy(eap_header, boffset, eap_len, 1);
			offset += eap_len;
	
			if(eap_type == EAP_EXPANDED)
			{
				//memcpy((void *) ((char *) buf+offset), wfa_header, wfa_len);
				Copy(wfa_header, boffset, wfa_len, 1);
				offset += wfa_len;
			}

			if(payload && payload_length)
			{
				//memcpy((void *) ((char *) buf+offset), payload, payload_length);
				Copy(payload, boffset, payload_length, 1);
			}
			int *len;
			*len = (offset + payload_length);
		}

		Safefree(snap_packet);
		Safefree(eap_header);
		Safefree(dot1x_header);
		if(wfa_header) {
			Safefree((void *) wfa_header);
	}
	}	
}
		return(buf);


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
	TIME start_time

void
pixie_format(key, length, outbuf)
	const unsigned char *key
	unsigned length
	char *outbuf

void
pixie_attack()
CODE:
	WPS_DATA *wps = get_wps();
	struct pixie *p = &pixie;
	int dh_small = get_dh_small();
	if(p->do_pixie) {
		char uptime_str[64];
		snprintf(uptime_str, sizeof(uptime_str), "-u %llu ", (unsigned long long) globule->uptime);
		snprintf(ptd.cmd, sizeof (ptd.cmd), "pixiewps %s-e %s -s %s -z %s -a %s -n %s %s %s", (p->use_uptime ? uptime_str : ""), p->pke, p->ehash1, p->ehash2, p->authkey, p->enonce, dh_small ? "-S" : "-r" , dh_small ? "" : p->pkr);
		printf("executing %s\n", ptd.cmd);
		ptd.pinlen = 64;
		ptd.pinbuf[0] = 0;
		if(pixie_run_thread(&ptd)) {
			cprintf(INFO, "[+] Pixiewps: success: setting pin to %s\n", ptd.pinbuf);
			set_pin(ptd.pinbuf);
			if(timeout_hit) {
				cprintf(VERBOSE, "[+] Pixiewps timeout hit, sent WSC NACK\n");
				cprintf(INFO, "[+] Pixiewps timeout, exiting. Send pin with -p\n");
				update_wpc_from_pin();
				exit(0);
			}
			Safefree(wps->dev_password);
			wps->dev_password = malloc(ptd.pinlen+1);
			//memcpy(wps->dev_password, ptd.pinbuf, ptd.pinlen+1);
			int pinlength = ptd.pinlen+1;
			Copy(ptd.pinbuf, wps->dev_password, pinlength, 1);
			wps->dev_password_len = ptd.pinlen;
		} else {
			cprintf(INFO, "[-] Pixiewps fail, sending WPS NACK\n");
			send_wsc_nack();
			exit(1);
		}
	}
	PIXIE_FREE(authkey);
	PIXIE_FREE(pkr);
	PIXIE_FREE(pke);
	PIXIE_FREE(enonce);
	PIXIE_FREE(ehash1);
	PIXIE_FREE(ehash2);

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
resend_last_packet()


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

	     
unsigned int 
wps_pin_checksum(pin)
	unsigned int pin
	
unsigned int 
wps_pin_valid(pin)
	unsigned int pin
	

unsigned int 
wps_generate_pin()


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

void
wps_kdf(key, label_prefix, label_prefix_len, label, res, res_len)
	const u8 *key
	const u8 *label_prefix
	size_t label_prefix_len
	const char *label
	u8 *res
	size_t res_len

int
wps_derive_keys(wps)
	WPS_DATA *wps
CODE:
	struct wpabuf *pubkey, *dh_shared;
	uint8_t dhkey[SHA256_MAC_LEN], kdk[SHA256_MAC_LEN];
	const u8 *addr[3];
	size_t len[3];
	u8 keys[WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN + WPS_EMSK_LEN];

	if (wps->dh_privkey == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Own DH private key not available");
		return -1;
	}

	pubkey = wps->registrar ? wps->dh_pubkey_e : wps->dh_pubkey_r;
	if (pubkey == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Peer DH public key not available");
		return -1;
	}

	wpa_hexdump_buf_key(MSG_DEBUG, "WPS: DH Private Key", wps->dh_privkey); 
	wpa_hexdump_buf(MSG_DEBUG, "WPS: DH peer Public Key", pubkey);
	dh_shared = dh5_derive_shared(wps->dh_ctx, pubkey, wps->dh_privkey);
	dh5_free(wps->dh_ctx);
	wps->dh_ctx = NULL;
	dh_shared = wpabuf_zeropad(dh_shared, 192);
	if (dh_shared == NULL) {
		wpa_printf(MSG_DEBUG, "WPS: Failed to derive DH shared key");
		return -1;
	}

	/* Own DH private key is not needed anymore */
	wpabuf_free(wps->dh_privkey);
	wps->dh_privkey = NULL;

	wpa_hexdump_buf_key(MSG_DEBUG, "WPS: DH shared key", dh_shared);

	/* DHKey = SHA-256(g^AB mod p) */
	addr[0] = wpabuf_head(dh_shared);
	len[0] = wpabuf_len(dh_shared);
	sha256_vector(1, addr, len, dhkey);
	wpa_hexdump_key(MSG_DEBUG, "WPS: DHKey", dhkey, sizeof(dhkey));
	wpabuf_free(dh_shared);

	/* KDK = HMAC-SHA-256_DHKey(N1 || EnrolleeMAC || N2) */
	addr[0] = wps->nonce_e;
	len[0] = WPS_NONCE_LEN;
	addr[1] = wps->mac_addr_e;
	len[1] = ETH_ALEN;
	addr[2] = wps->nonce_r;
	len[2] = WPS_NONCE_LEN;
	hmac_sha256_vector(dhkey, sizeof(dhkey), 3, addr, len, kdk);
	wpa_hexdump_key(MSG_DEBUG, "WPS: KDK", kdk, sizeof(kdk));

	wps_kdf(kdk, NULL, 0, "Wi-Fi Easy and Secure Key Derivation", keys, sizeof(keys));
	os_memcpy(wps->authkey, keys, WPS_AUTHKEY_LEN);
	os_memcpy(wps->keywrapkey, keys + WPS_AUTHKEY_LEN, WPS_KEYWRAPKEY_LEN);
	os_memcpy(wps->emsk, keys + WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN, WPS_EMSK_LEN);
	wpa_hexdump_key(MSG_DEBUG, "WPS: AuthKey",
			wps->authkey, WPS_AUTHKEY_LEN);
	wpa_hexdump_key(MSG_DEBUG, "WPS: KeyWrapKey",
			wps->keywrapkey, WPS_KEYWRAPKEY_LEN);
	wpa_hexdump_key(MSG_DEBUG, "WPS: EMSK", wps->emsk, WPS_EMSK_LEN);

	if(pixie.do_pixie) {
		char buf[4096];
		pixie_format(wps->authkey, WPS_AUTHKEY_LEN, buf);
		PIXIE_SET(authkey, buf);
	}

	return 0;

	
	
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
	const WPA_BUF *msg
	WPS_PARSE_ATTR *attr
	
	

int
wps_build_public_key(wps, msg)
	WPS_DATA *wps
	WPA_BUF *msg

int
wps_build_config_methods(msg, methods)
	WPA_BUF *msg
	u16 methods

int
wps_build_uuid_e(msg, uuid)
	WPA_BUF *msg
	const u8 *uuid

int
wps_build_dev_password_id(msg, id)
	WPA_BUF *msg
	u16 id

int
wps_build_config_error(msg, err)
	WPA_BUF *msg
	u16 err	

int
wps_build_authenticator(wps, msg)
	WPA_BUF *wps
	WPA_BUF *msg

int
wps_build_key_wrap_auth(wps, msg)	
	WPS_DATA *wps
	WPA_BUF *msg

int
wps_build_encr_settings(wps, msg, plain)
	WPS_DATA *wps
	WPA_BUF *msg
	WPA_BUF *plain

int
wps_build_version(msg)
	WPA_BUF *msg

int
wps_build_msg_type(msg, msg_type)
	WPA_BUF *msg
	WPS_MESSAGE_TYPE msg_type

int
wps_build_enrollee_nonce(wps, msg)
	WPS_DATA *wps
	WPA_BUF *msg

int	
wps_build_registrar_nonce(wps, msg)
	WPS_DATA *wps
	WPA_BUF *msg

int
wps_build_auth_type_flags(wps, msg)
	WPS_DATA *wps
	WPA_BUF *msg

int
wps_build_encr_type_flags(wps, msg)
	WPS_DATA *wps
	WPA_BUF *msg

int
wps_build_conn_type_flags(wps, msg)
	WPS_DATA *wps
	WPA_BUF *msg

int
wps_build_assoc_state(wps, msg)
	WPS_DATA *wps
	WPA_BUF *msg

int
wps_build_oob_dev_password(msg, wps)
	WPA_BUF *msg
	WPS_CONTEXT *wps

int
wps_process_authenticator(wps, authenticator, msg)
	WPS_DATA *wps
	const u8 *authenticator
	const WPA_BUF *msg

int
wps_process_key_wrap_auth(wps, msg, key_wrap_auth)
	WPS_DATA *wps
	WPA_BUF *msg
	const u8 *key_wrap_auth

int
wps_process_cred(attr, cred)
	WPS_PARSE_ATTR *attr
	WPS_CREDENTIAL *cred

int
wps_process_ap_settings(attr, cred)
	WPS_PARSE_ATTR *attr
	WPS_CREDENTIAL *cred

WPA_BUF *
wps_enrollee_get_msg(wps, op_code)
	WPS_DATA *wps
	WSC_OP_CODE *op_code
	
WPS_PROCESS_RES
wps_enrollee_process_msg(wps,op_code, msg)
	WPS_DATA *wps
	WSC_OP_CODE op_code
	const WPA_BUF *msg
	
WPA_BUF *
wps_registrar_get_msg(wps, op_code, type)
	WPS_DATA *wps
	WSC_OP_CODE *op_code
	int type
	
int
wps_build_cred(wps,msg)
	WPS_DATA *wps
	WPA_BUF *msg

int
wps_device_store(reg, dev, uuid)
	WPS_REGISTRAR *reg
	WPS_DEVICE_DATA *dev
	const u8 *uuid
	
void
wps_registrar_selected_registrar_changed(reg)
	WPS_REGISTRAR *reg

int
wps_er_pbc(er, uuid)
	WPS_ER *er
	const u8 *uuid

int
wps_er_learn(er, uuid, pin,  pin_len)
	WPS_ER *er
	const u8 *uuid
	const u8 *pin
	size_t pin_len

int
wps_build_device_attrs(dev, msg)
	WPS_DEVICE_DATA *dev
	WPA_BUF *msg

int
wps_build_os_version(dev, msg)
	WPS_DEVICE_DATA *dev
	WPA_BUF *msg
	
int
wps_build_rf_bands(dev, msg)
	WPS_DEVICE_DATA *dev
	WPA_BUF *msg
	
int
wps_build_primary_dev_type(dev, msg)
	WPS_DEVICE_DATA *dev
	WPA_BUF *msg

int
wps_process_device_attrs(dev, attr)
	WPS_DEVICE_DATA *dev
	WPS_PARSE_ATTR *attr

int
wps_process_os_version(dev, ver)
	WPS_DEVICE_DATA *dev
	const u8 *ver
	

void
wps_device_data_dup(dst, src)
	WPS_DEVICE_DATA *dst
	const WPS_DEVICE_DATA *src
	
void
wps_device_data_free(dev)
	WPS_DEVICE_DATA *dev
	
int
parse_wps_tag(tags, length, wps)
	const u_char *tags
	size_t length
	LIBWPS_DATA *wps
	
unsigned char *
get_wps_data(data, length, tag_len)
	const u_char *data
	size_t length
	size_t *tag_len

unsigned char *
get_wps_data_element(data,  length, type, el_len)
	const u_char *data 
	size_t length
	uint16_t type
	size_t *el_len

int
libwps_has_rt_header(packet, length)
	const u_char *packet
	size_t length

const u_char *
libwps_radio_header(packet, length)
	const u_char *packet
	size_t length

int
wpa_eapol_key_mic(key, ver, buf, length, mic)
	const u8 *key
	int ver
	const u8 *buf
	size_t length
	u8 *mic

void
wpa_pmk_to_ptk(pmk, pmk_len, label, addr1, addr2, nonce1, nonce2, ptk, ptk_len, use_sha256)
	const u8 *pmk
	size_t pmk_len
	const char *label
	const u8 *addr1
	const u8 *addr2
	const u8 *nonce1
	const u8 *nonce2
	u8 *ptk
	size_t ptk_len
	int use_sha256
	
int
wpa_ft_mic(kck, sta_addr, ap_addr, transaction_seqnum, mdie, mdie_len, ftie, ftie_len, rsnie, rsnie_len, ric, ric_len, mic)
	const u8 *kck
	const u8 *sta_addr
	const u8 *ap_addr
	u8 transaction_seqnum
	const u8 *mdie
	size_t mdie_len
	const u8 *ftie
	size_t ftie_len
	const u8 *rsnie
	size_t rsnie_len
	const u8 *ric
	size_t ric_len
	u8 *mic

void
wpa_derive_pmk_r0(xxkey, xxkey_len, ssid, ssid_len, mdid, r0kh_id, r0kh_id_len, s0kh_id, pmk_r0, pmk_r0_name)
	const u8 *xxkey
	size_t xxkey_len
	const u8 *ssid
	size_t ssid_len
	const u8 *mdid
	const u8 *r0kh_id
	size_t r0kh_id_len
	const u8 *s0kh_id
	u8 *pmk_r0
	u8 *pmk_r0_name

void
wpa_derive_pmk_r1_name(pmk_r0_name, r1kh_id, s1kh_id, pmk_r1_name)
	const u8 *pmk_r0_name
	const u8 *r1kh_id
	const u8 *s1kh_id
	u8 *pmk_r1_name

void
wpa_derive_pmk_r1(pmk_r0, pmk_r0_name, r1kh_id, s1kh_id, pmk_r1, pmk_r1_name)
	const u8 *pmk_r0
	const u8 *pmk_r0_name
	const u8 *r1kh_id
	const u8 *s1kh_id
	u8 *pmk_r1
	u8 *pmk_r1_name

void
wpa_pmk_r1_to_ptk(pmk_r1, snonce, anonce, sta_addr, bssid, pmk_r1_name, ptk, ptk_len, ptk_name)
	const u8 *pmk_r1
	const u8 *snonce
	const u8 *anonce
	const u8 *sta_addr
	const u8 *bssid
	const u8 *pmk_r1_name
	u8 *ptk 
	size_t ptk_len
	u8 *ptk_name


int
wpa_parse_wpa_ie_rsn(rsn_ie, rsn_ie_len, data)
	const u8 *rsn_ie
	size_t rsn_ie_len
	WPA_IE_DATA *data

void
rsn_pmkid(pmk, pmk_len, aa, spa, pmkid, use_sha256)
	const u8 *pmk
	size_t pmk_len
	const u8*aa
	const u8 *spa
	u8 *pmkid
	int use_sha256

const char * 
wpa_cipher_txt(cipher)
	int cipher
CODE:
switch (cipher) {
	case WPA_CIPHER_NONE:
		return "NONE";
	case WPA_CIPHER_WEP40:
		return "WEP-40";
	case WPA_CIPHER_WEP104:
		return "WEP-104";
	case WPA_CIPHER_TKIP:
		return "TKIP";
	case WPA_CIPHER_CCMP:
		return "CCMP";
	case WPA_CIPHER_CCMP | WPA_CIPHER_TKIP:
		return "CCMP+TKIP";
	default:
		return "UNKNOWN";
	}

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

int
wpa_insert_pmkid(ies, ies_len, pmkid)
	u8 *ies
	size_t ies_len
	const u8 *pmkid
