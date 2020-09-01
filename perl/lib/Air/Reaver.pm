# Made by Edoardo Mantovani, 2020

package Air::Reaver;
require  v5.22.1;

# initial release

use strict;
use warnings;


our $VERSION = '17.7';
use base qw(Exporter DynaLoader);

use constant {
DEAUTH_REASON_CODE => '\x03\x00',
   DEAUTH_REASON_CODE_SIZE => 2,
   WPS_REGISTRAR_TAG => '\x00\x50\xF2\x04\x10\x4A\x00\x01\x10\x10\x3A\x00\x01\x02',
   OPEN_SYSTEM => 0,
   WFA_VENDOR_ID => '\x00\x37\x2A',
   NULL_MAC => '\x00\x00\x00\x00\x00\x00',
   TIMESTAMP_LEN => 8,
   MAC_ADDR_LEN => 6,
   SSID_TAG_NUMBER => 0,
   RATES_TAG_NUMBER => 1,
   CHANNEL_TAG_NUMBER => 3,
   WPA_IE_ID => '\x00\x50\xF2\x01\x01\x00',
   WPA_IE_ID_LEN => 6,
   EAPOL_START => 1,
   DEFAULT_DELAY => 1,
   WPS_DEVICE_NAME => "Glau",
   WPS_MANUFACTURER => "Microsoft",
   WPS_MODEL_NAME => "Windows",
   WPS_MODEL_NUMBER => "6.1.7601",
   WPS_DEVICE_TYPE => '\x00\x01\x00\x50\xF2\x04\x00\x01',
   WPS_OS_VERSION => '\x01\x00\x06\x00',
   DEFAULT_UUID => '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',
   WFA_REGISTRAR => "WFA-SimpleConfig-Registrar-1-0",
   CONF_DIR => "/etc/reaver",
   CONF_EXT => "wpc",
   BELL => '\x07',
   WPS_VENDOR_ID => '\x00\x50\xF2\x04',
   WPS_VENDOR_ID_SIZE => 4,
   VENDOR_ID_OFFSET => 2,
   LENGTH_OFFSET => 1,
   SURVEY => 0,
   SCAN => 1,
   YES => "Yes",
   NO => "No",
   NO_REPLAY_HTCAPS => 0,
   FAKE_RADIO_TAP_HEADER => '\0\0\0\0',
   TAG_SUPPORTED_RATES => '\x01\x08\x02\x04\x0b\x16\x0c\x12\x18\x24',
   TAG_EXT_RATES => '\x32\x04\x30\x48\x60\x6c',
   TAG_HT_CAPS => '\x2d\x1a\x72\x01\x13\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
   WPS_PROBE_IE => '\xdd\x09\x00\x50\xf2\x04\x10\x4a\x00\x01\x10',
   BG_CHANNELS => 14,
   AN_CHANNELS => 16,
   C_REAVER => 0,
   C_WASH => 1
};

our %EXPORT_TAGS = (
   reaver => [qw(
      build_radio_tap_header
      build_association_management_frame
      build_authentication_management_frame
      build_supported_rates_tagged_parameter
      build_htcaps_parameter
      build_wps_probe_request
      build_snap_packet
      build_dot1X_header
      build_eap_header
      build_eapol_start_packet
      build_eap_packet
      build_eap_failure_packet
      crack
      advance_pin_count
      display_status
      pixie_format
      pixie_attack
      build_wps_pin
      build_next_pin
      generate_pins
      send_eapol_start
      send_identity_response
      send_msg
      send_termination
      send_wsc_nack
      resend_last_packet
      send_packet_internal
      wps_registrar_init
      wps_registrar_deinit
      wps_registrar_add_pin
      wps_registrar_invalidate_pin
      wps_registrar_unlock_pin
      wps_registrar_button_pushed
      wps_registrar_probe_req_rx
      wps_registrar_update_ie
      wps_registrar_get_info
      wps_pin_checksum
      wps_pin_valid
      wps_generate_pin
      wps_get_oob_method
      wps_attr_text
      wps_er_init
      wps_er_refresh
      wps_er_set_sel_reg
      wps_kdf
      wps_derive_keys
      wps_derive_psk
      wps_decrypt_encr_settings
      wps_success_event
      wps_pwd_auth_fail_event
      wps_pbc_overlap_event
      wps_pbc_timeout_event
      wps_parse_msg
      wps_build_public_key
      wps_build_config_methods
      wps_build_uuid_e
      wps_build_dev_password_id
      wps_build_config_error
      wps_build_authenticator
      wps_build_key_wrap_auth
      wps_build_encr_settings
      wps_build_version
      wps_build_msg_type
      wps_build_enrollee_nonce
      wps_build_registrar_nonce
      wps_build_auth_type_flags
      wps_build_encr_type_flags
      wps_build_conn_type_flags
      wps_build_assoc_state
      wps_build_oob_dev_password
      wps_process_authenticator
      wps_process_key_wrap_auth
      wps_process_cred
      wps_process_ap_settings
      wps_enrollee_get_msg
      wps_enrollee_process_msg
      wps_registrar_get_msg
      wps_build_cred
      wps_device_store
      wps_registrar_selected_registrar_changed
      wps_er_pbc
      wps_er_learn
      wps_build_device_attrs
      wps_build_os_version
      wps_build_rf_bands
      wps_build_primary_dev_type
      wps_process_device_attrs
      wps_process_os_version
      wps_device_data_dup
      wps_device_data_free
      parse_wps_tag
      get_wps_data
      get_wps_data_element
      libwps_has_rt_header
      libwps_radio_header
      wpa_eapol_key_mic
      wpa_pmk_to_ptk
      wpa_ft_mic
      wpa_derive_pmk_r0
      wpa_derive_pmk_r1_name
      wpa_derive_pmk_r1
      wpa_pmk_r1_to_ptk
      wpa_parse_wpa_ie_rsn
      rsn_pmkid
      wpa_cipher_txt
      wpa_key_mgmt_txt
      wpa_compare_rsn_ie
      wpa_insert_pmkid
      
      
    )],
    
   constants => [qw(
   
   DEAUTH_REASON_CODE
   DEAUTH_REASON_CODE_SIZE
   WPS_REGISTRAR_TAG
   OPEN_SYSTEM
   WFA_VENDOR_ID
   NULL_MAC
   TIMESTAMP_LEN
   MAC_ADDR_LEN
   SSID_TAG_NUMBER
   RATES_TAG_NUMBER
   CHANNEL_TAG_NUMBER
   WPA_IE_ID
   WPA_IE_ID_LEN
   EAPOL_START
   DEFAULT_DELAY
   WPS_DEVICE_NAME
   WPS_MANUFACTURER
   WPS_MODEL_NAME
   WPS_MODEL_NUMBER
   WPS_DEVICE_TYPE
   WPS_OS_VERSION
   DEFAULT_UUID
   WFA_REGISTRAR
   CONF_DIR
   CONF_EXT
   BELL
   WPS_VENDOR_ID
   WPS_VENDOR_ID_SIZE
   VENDOR_ID_OFFSET
   LENGTH_OFFSET
   SURVEY
   SCAN
   YES
   NO
   NO_REPLAY_HTCAPS
   PROBE_RESP_SIZE(rth_len)
   FAKE_RADIO_TAP_HEADER
   TAG_SUPPORTED_RATES
   TAG_EXT_RATES
   TAG_HT_CAPS
   WPS_PROBE_IE
   BG_CHANNELS
   AN_CHANNELS
   C_REAVER
   C_WASH

   )],
);

our @EXPORT = (
   @{ $EXPORT_TAGS{ reaver} },
   @{ $EXPORT_TAGS{ constants } },
);



__PACKAGE__->bootstrap($VERSION);


1;

__END__

