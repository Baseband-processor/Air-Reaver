package Air::Reaver;
require  v5.22.1;

# initial release

use strict;
use warnings;


our $VERSION = '0.1';
use base qw(Exporter DynaLoader);

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

);

our @EXPORT = (
   @{ $EXPORT_TAGS{reaver} },

);



__PACKAGE__->bootstrap($VERSION);


1;

__END__

