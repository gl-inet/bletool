/*****************************************************************************
 * @file 
 * @brief 
 *******************************************************************************
 Copyright 2020 GL-iNet. https://www.gl-inet.com/

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 ******************************************************************************/

#ifndef HOST_GECKO_H
#define HOST_GECKO_H

#include <string.h>
#include "bg_types.h"
#include "gecko_configuration.h"
#include "bg_errorcodes.h"
#include "timestamp.h"



/* Compatibility */
#ifndef PACKSTRUCT
/*Default packed configuration*/
#ifdef __GNUC__
#ifdef _WIN32
#define PACKSTRUCT( decl ) decl __attribute__((__packed__,gcc_struct))
#else
#define PACKSTRUCT( decl ) decl __attribute__((__packed__))
#endif
#define ALIGNED __attribute__((aligned(0x4)))
#elif __IAR_SYSTEMS_ICC__

#define PACKSTRUCT( decl ) __packed decl

#define ALIGNED
#elif _MSC_VER  /*msvc*/

#define PACKSTRUCT( decl ) __pragma( pack(push, 1) ) decl __pragma( pack(pop) )
#define ALIGNED
#else 
#define PACKSTRUCT(a) a PACKED 
#endif
#endif


#define BGLIB_DEPRECATED_API __attribute__((deprecated))
#define BGLIB_MSG_ID(HDR) ((HDR)&0xffff00f8)
#define BGLIB_MSG_HEADER_LEN (4)
#define BGLIB_MSG_LEN(HDR) ((((HDR)&0x7)<<8)|(((HDR)&0xff00)>>8))

/**
 * The maximum BGAPI command payload size.
 */
#define BGLIB_MSG_MAX_PAYLOAD 256

/*Pass in the endian*/
extern unsigned char ENDIAN;

/*Reverse the byte order*/
void reverse_endian(uint8_t* header,uint8_t length);

#define BGLIB_BIT_ENCRYPTED (1 << 6) // Bit indicating whether the packet is encrypted
#define BGLIB_MSG_ENCRYPTED(HDR) ((HDR) & BGLIB_BIT_ENCRYPTED)


enum le_gap_address_type
{
    le_gap_address_type_public                                   = 0x0,
    le_gap_address_type_random                                   = 0x1,
    le_gap_address_type_public_identity                          = 0x2,
    le_gap_address_type_random_identity                          = 0x3
};

enum le_gap_phy_type
{
    le_gap_phy_1m                                                = 0x1,
    le_gap_phy_2m                                                = 0x2,
    le_gap_phy_coded                                             = 0x4
};

enum le_gap_connectable_mode
{
    le_gap_non_connectable                                       = 0x0,
    le_gap_directed_connectable                                  = 0x1,
    le_gap_undirected_connectable                                = 0x2,
    le_gap_connectable_scannable                                 = 0x2,
    le_gap_scannable_non_connectable                             = 0x3,
    le_gap_connectable_non_scannable                             = 0x4
};

enum le_gap_discoverable_mode
{
    le_gap_non_discoverable                                      = 0x0,
    le_gap_limited_discoverable                                  = 0x1,
    le_gap_general_discoverable                                  = 0x2,
    le_gap_broadcast                                             = 0x3,
    le_gap_user_data                                             = 0x4
};

enum le_gap_discover_mode
{
    le_gap_discover_limited                                      = 0x0,
    le_gap_discover_generic                                      = 0x1,
    le_gap_discover_observation                                  = 0x2
};

enum le_gap_adv_address_type
{
    le_gap_identity_address                                      = 0x0,
    le_gap_non_resolvable                                        = 0x1
};

enum sync_advertiser_clock_accuracy
{
    sync_clock_accuracy_500                                      = 0x1f4,
    sync_clock_accuracy_250                                      = 0xfa,
    sync_clock_accuracy_150                                      = 0x96,
    sync_clock_accuracy_100                                      = 0x64,
    sync_clock_accuracy_75                                       = 0x4b,
    sync_clock_accuracy_50                                       = 0x32,
    sync_clock_accuracy_30                                       = 0x1e,
    sync_clock_accuracy_20                                       = 0x14
};

enum le_connection_security
{
    le_connection_mode1_level1                                   = 0x0,
    le_connection_mode1_level2                                   = 0x1,
    le_connection_mode1_level3                                   = 0x2,
    le_connection_mode1_level4                                   = 0x3
};

enum gatt_att_opcode
{
    gatt_read_by_type_request                                    = 0x8,
    gatt_read_by_type_response                                   = 0x9,
    gatt_read_request                                            = 0xa,
    gatt_read_response                                           = 0xb,
    gatt_read_blob_request                                       = 0xc,
    gatt_read_blob_response                                      = 0xd,
    gatt_read_multiple_request                                   = 0xe,
    gatt_read_multiple_response                                  = 0xf,
    gatt_write_request                                           = 0x12,
    gatt_write_response                                          = 0x13,
    gatt_write_command                                           = 0x52,
    gatt_prepare_write_request                                   = 0x16,
    gatt_prepare_write_response                                  = 0x17,
    gatt_execute_write_request                                   = 0x18,
    gatt_execute_write_response                                  = 0x19,
    gatt_handle_value_notification                               = 0x1b,
    gatt_handle_value_indication                                 = 0x1d
};

enum gatt_client_config_flag
{
    gatt_disable                                                 = 0x0,
    gatt_notification                                            = 0x1,
    gatt_indication                                              = 0x2
};

enum gatt_execute_write_flag
{
    gatt_cancel                                                  = 0x0,
    gatt_commit                                                  = 0x1
};

enum gatt_server_characteristic_status_flag
{
    gatt_server_client_config                                    = 0x1,
    gatt_server_confirmation                                     = 0x2
};


enum test_packet_type
{
    test_pkt_prbs9                                               = 0x0,
    test_pkt_11110000                                            = 0x1,
    test_pkt_10101010                                            = 0x2,
    test_pkt_11111111                                            = 0x4,
    test_pkt_00000000                                            = 0x5,
    test_pkt_00001111                                            = 0x6,
    test_pkt_01010101                                            = 0x7,
    test_pkt_pn9                                                 = 0xfd,
    test_pkt_carrier                                             = 0xfe
};

enum test_phy
{
    test_phy_1m                                                  = 0x1,
    test_phy_2m                                                  = 0x2,
    test_phy_125k                                                = 0x3,
    test_phy_500k                                                = 0x4
};

enum sm_bonding_key
{
    sm_bonding_key_ltk                                           = 0x1,
    sm_bonding_key_addr_public                                   = 0x2,
    sm_bonding_key_addr_static                                   = 0x4,
    sm_bonding_key_irk                                           = 0x8,
    sm_bonding_key_edivrand                                      = 0x10,
    sm_bonding_key_csrk                                          = 0x20,
    sm_bonding_key_masterid                                      = 0x40
};

enum sm_io_capability
{
    sm_io_capability_displayonly                                 = 0x0,
    sm_io_capability_displayyesno                                = 0x1,
    sm_io_capability_keyboardonly                                = 0x2,
    sm_io_capability_noinputnooutput                             = 0x3,
    sm_io_capability_keyboarddisplay                             = 0x4
};

enum homekit_category
{
    homekit_not_allowed                                          = 0x0,
    homekit_other                                                = 0x1,
    homekit_bridge                                               = 0x2,
    homekit_fan                                                  = 0x3,
    homekit_garage                                               = 0x4,
    homekit_lightbulb                                            = 0x5,
    homekit_doorlock                                             = 0x6,
    homekit_outlet                                               = 0x7,
    homekit_switch_accessory                                     = 0x8,
    homekit_thermostat                                           = 0x9,
    homekit_sensor                                               = 0xa,
    homekit_security_system                                      = 0xb,
    homekit_door                                                 = 0xc,
    homekit_window                                               = 0xd,
    homekit_window_covering                                      = 0xe,
    homekit_programmable_switch                                  = 0xf,
    homekit_ip_camera                                            = 0x11,
    homekit_video_door_bell                                      = 0x12,
    homekit_air_purifier                                         = 0x13,
    homekit_heater                                               = 0x14,
    homekit_air_conditioner                                      = 0x15,
    homekit_humidifier                                           = 0x16,
    homekit_dehumidifier                                         = 0x17,
    homekit_sprinkler                                            = 0x1c,
    homekit_faucet                                               = 0x1d,
    homekit_shower_system                                        = 0x1e,
    homekit_remote                                               = 0x20
};

enum homekit_status_code
{
    homekit_success                                              = 0x0,
    homekit_invalid_request                                      = 0x6
};

enum coex_option
{
    coex_option_enable                                           = 0x100,
    coex_option_tx_abort                                         = 0x400,
    coex_option_high_priority                                    = 0x800
};

enum l2cap_coc_connection_result
{
    l2cap_connection_successful                                  = 0x0,
    l2cap_le_psm_not_supported                                   = 0x2,
    l2cap_no_resources_available                                 = 0x4,
    l2cap_insufficient_authentication                            = 0x5,
    l2cap_insufficient_authorization                             = 0x6,
    l2cap_insufficient_encryption_key_size                       = 0x7,
    l2cap_insufficient_encryption                                = 0x8,
    l2cap_invalid_source_cid                                     = 0x9,
    l2cap_source_cid_already_allocated                           = 0xa,
    l2cap_unacceptable_parameters                                = 0xb
};

enum l2cap_command_reject_reason
{
    l2cap_command_not_understood                                 = 0x0,
    l2cap_signaling_mtu_exceeded                                 = 0x1,
    l2cap_invalid_cid_request                                    = 0x2
};

enum l2cap_command_code
{
    l2cap_l2cap_disconnection_request                            = 0x6,
    l2cap_l2cap_connection_request                               = 0x14,
    l2cap_l2cap_flow_control_credit                              = 0x16
};

enum gecko_parameter_types
{
    gecko_msg_parameter_uint8=2,
    gecko_msg_parameter_int8=3,
    gecko_msg_parameter_uint16=4,
    gecko_msg_parameter_int16=5,
    gecko_msg_parameter_uint32=6,
    gecko_msg_parameter_int32=7,
    gecko_msg_parameter_uint8array=8,
    gecko_msg_parameter_string=9,
    gecko_msg_parameter_hwaddr=10,
    gecko_msg_parameter_uint16array=11
};

enum gecko_msg_types
{
    gecko_msg_type_cmd=0x00,
    gecko_msg_type_rsp=0x00,
    gecko_msg_type_evt=0x80
};
enum gecko_dev_types
{
    gecko_dev_type_gecko   =0x20
};



#define FLASH_PS_KEY_LOCAL_BD_ADDR                                   0x2c
#define FLASH_PS_KEY_TX_POWER                                        0x31
#define FLASH_PS_KEY_CTUNE                                           0x32
#define FLASH_PS_KEY_APPLICATION_GSN                                 0x33
#define FLASH_PS_KEY_OTA_FLAGS                                       0x35
#define FLASH_PS_KEY_OTA_DEVICE_NAME                                 0x36
#define FLASH_PS_KEY_DEVICE_IRK                                      0x37
#define FLASH_PS_KEY_BONDING_PRIORITY_LIST                           0x38
#define FLASH_PS_KEY_OTA_ADVERTISEMENT_PACKET                        0x39
#define FLASH_PS_KEY_OTA_SCAN_RESPONSE_PACKET                        0x3a
#define FLASH_PS_KEY_APPLICATION_AI                                  0x3b
#define FLASH_PS_KEY_IDENTITY_ADDR_TYPE                              0x3c
#define FLASH_PS_KEY_GATT_DB_HASH                                    0x3d
#define FLASH_PS_KEY_BONDING_DB_CONFIG                               0x3fff


#define gecko_cmd_dfu_reset_id                                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x00000000)
#define gecko_cmd_dfu_flash_set_address_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x01000000)
#define gecko_cmd_dfu_flash_upload_id                                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x02000000)
#define gecko_cmd_dfu_flash_upload_finish_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x03000000)
#define gecko_cmd_system_hello_id                                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x00010000)
#define gecko_cmd_system_reset_id                                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x01010000)
#define gecko_cmd_system_get_bt_address_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x03010000)
#define gecko_cmd_system_set_bt_address_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x04010000)
#define gecko_cmd_system_set_tx_power_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0a010000)
#define gecko_cmd_system_get_random_data_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0b010000)
#define gecko_cmd_system_halt_id                                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0c010000)
#define gecko_cmd_system_set_device_name_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0d010000)
#define gecko_cmd_system_linklayer_configure_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0e010000)
#define gecko_cmd_system_get_counters_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0f010000)
#define gecko_cmd_system_set_identity_address_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x13010000)
#define gecko_cmd_le_gap_open_id                                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x00030000)
#define gecko_cmd_le_gap_set_mode_id                                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x01030000)
#define gecko_cmd_le_gap_discover_id                                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x02030000)
#define gecko_cmd_le_gap_end_procedure_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x03030000)
#define gecko_cmd_le_gap_set_adv_parameters_id                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x04030000)
#define gecko_cmd_le_gap_set_conn_parameters_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x05030000)
#define gecko_cmd_le_gap_set_scan_parameters_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x06030000)
#define gecko_cmd_le_gap_set_adv_data_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x07030000)
#define gecko_cmd_le_gap_set_adv_timeout_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x08030000)
#define gecko_cmd_le_gap_bt5_set_mode_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0a030000)
#define gecko_cmd_le_gap_bt5_set_adv_parameters_id                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0b030000)
#define gecko_cmd_le_gap_bt5_set_adv_data_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0c030000)
#define gecko_cmd_le_gap_set_privacy_mode_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0d030000)
#define gecko_cmd_le_gap_set_advertise_timing_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0e030000)
#define gecko_cmd_le_gap_set_advertise_channel_map_id                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0f030000)
#define gecko_cmd_le_gap_set_advertise_report_scan_request_id         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x10030000)
#define gecko_cmd_le_gap_set_advertise_phy_id                         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x11030000)
#define gecko_cmd_le_gap_set_advertise_configuration_id               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x12030000)
#define gecko_cmd_le_gap_clear_advertise_configuration_id             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x13030000)
#define gecko_cmd_le_gap_start_advertising_id                         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x14030000)
#define gecko_cmd_le_gap_stop_advertising_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x15030000)
#define gecko_cmd_le_gap_set_discovery_timing_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x16030000)
#define gecko_cmd_le_gap_set_discovery_type_id                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x17030000)
#define gecko_cmd_le_gap_start_discovery_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x18030000)
#define gecko_cmd_le_gap_set_data_channel_classification_id           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x19030000)
#define gecko_cmd_le_gap_connect_id                                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x1a030000)
#define gecko_cmd_le_gap_set_advertise_tx_power_id                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x1b030000)
#define gecko_cmd_le_gap_set_discovery_extended_scan_response_id      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x1c030000)
#define gecko_cmd_le_gap_start_periodic_advertising_id                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x1d030000)
#define gecko_cmd_le_gap_stop_periodic_advertising_id                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x1f030000)
#define gecko_cmd_le_gap_enable_whitelisting_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x21030000)
#define gecko_cmd_sync_open_id                                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x00420000)
#define gecko_cmd_sync_close_id                                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x01420000)
#define gecko_cmd_le_connection_set_parameters_id                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x00080000)
#define gecko_cmd_le_connection_get_rssi_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x01080000)
#define gecko_cmd_le_connection_disable_slave_latency_id              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x02080000)
#define gecko_cmd_le_connection_set_phy_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x03080000)
#define gecko_cmd_le_connection_close_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x04080000)
#define gecko_cmd_gatt_set_max_mtu_id                                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x00090000)
#define gecko_cmd_gatt_discover_primary_services_id                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x01090000)
#define gecko_cmd_gatt_discover_primary_services_by_uuid_id           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x02090000)
#define gecko_cmd_gatt_discover_characteristics_id                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x03090000)
#define gecko_cmd_gatt_discover_characteristics_by_uuid_id            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x04090000)
#define gecko_cmd_gatt_set_characteristic_notification_id             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x05090000)
#define gecko_cmd_gatt_discover_descriptors_id                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x06090000)
#define gecko_cmd_gatt_read_characteristic_value_id                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x07090000)
#define gecko_cmd_gatt_read_characteristic_value_by_uuid_id           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x08090000)
#define gecko_cmd_gatt_write_characteristic_value_id                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x09090000)
#define gecko_cmd_gatt_write_characteristic_value_without_response_id  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0a090000)
#define gecko_cmd_gatt_prepare_characteristic_value_write_id          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0b090000)
#define gecko_cmd_gatt_execute_characteristic_value_write_id          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0c090000)
#define gecko_cmd_gatt_send_characteristic_confirmation_id            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0d090000)
#define gecko_cmd_gatt_read_descriptor_value_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0e090000)
#define gecko_cmd_gatt_write_descriptor_value_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0f090000)
#define gecko_cmd_gatt_find_included_services_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x10090000)
#define gecko_cmd_gatt_read_multiple_characteristic_values_id         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x11090000)
#define gecko_cmd_gatt_read_characteristic_value_from_offset_id       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x12090000)
#define gecko_cmd_gatt_prepare_characteristic_value_reliable_write_id  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x13090000)
#define gecko_cmd_gatt_server_read_attribute_value_id                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x000a0000)
#define gecko_cmd_gatt_server_read_attribute_type_id                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x010a0000)
#define gecko_cmd_gatt_server_write_attribute_value_id                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x020a0000)
#define gecko_cmd_gatt_server_send_user_read_response_id              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x030a0000)
#define gecko_cmd_gatt_server_send_user_write_response_id             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x040a0000)
#define gecko_cmd_gatt_server_send_characteristic_notification_id     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x050a0000)
#define gecko_cmd_gatt_server_find_attribute_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x060a0000)
#define gecko_cmd_gatt_server_set_capabilities_id                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x080a0000)
#define gecko_cmd_hardware_set_soft_timer_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x000c0000)
#define gecko_cmd_hardware_get_time_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0b0c0000)
#define gecko_cmd_hardware_set_lazy_soft_timer_id                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0c0c0000)
#define gecko_cmd_flash_ps_erase_all_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x010d0000)
#define gecko_cmd_flash_ps_save_id                                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x020d0000)
#define gecko_cmd_flash_ps_load_id                                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x030d0000)
#define gecko_cmd_flash_ps_erase_id                                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x040d0000)
#define gecko_cmd_test_dtm_tx_id                                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x000e0000)
#define gecko_cmd_test_dtm_rx_id                                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x010e0000)
#define gecko_cmd_test_dtm_end_id                                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x020e0000)
#define gecko_cmd_sm_set_bondable_mode_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x000f0000)
#define gecko_cmd_sm_configure_id                                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x010f0000)
#define gecko_cmd_sm_store_bonding_configuration_id                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x020f0000)
#define gecko_cmd_sm_increase_security_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x040f0000)
#define gecko_cmd_sm_delete_bonding_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x060f0000)
#define gecko_cmd_sm_delete_bondings_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x070f0000)
#define gecko_cmd_sm_enter_passkey_id                                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x080f0000)
#define gecko_cmd_sm_passkey_confirm_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x090f0000)
#define gecko_cmd_sm_set_oob_data_id                                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0a0f0000)
#define gecko_cmd_sm_list_all_bondings_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0b0f0000)
#define gecko_cmd_sm_bonding_confirm_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0e0f0000)
#define gecko_cmd_sm_set_debug_mode_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x0f0f0000)
#define gecko_cmd_sm_set_passkey_id                                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x100f0000)
#define gecko_cmd_sm_use_sc_oob_id                                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x110f0000)
#define gecko_cmd_sm_set_sc_remote_oob_data_id                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x120f0000)
#define gecko_cmd_sm_add_to_whitelist_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x130f0000)
#define gecko_cmd_homekit_configure_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x00130000)
#define gecko_cmd_homekit_advertise_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x01130000)
#define gecko_cmd_homekit_delete_pairings_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x02130000)
#define gecko_cmd_homekit_check_authcp_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x03130000)
#define gecko_cmd_homekit_get_pairing_id_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x04130000)
#define gecko_cmd_homekit_send_write_response_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x05130000)
#define gecko_cmd_homekit_send_read_response_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x06130000)
#define gecko_cmd_homekit_gsn_action_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x07130000)
#define gecko_cmd_homekit_event_notification_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x08130000)
#define gecko_cmd_homekit_broadcast_action_id                         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x09130000)
#define gecko_cmd_coex_set_options_id                                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x00200000)
#define gecko_cmd_coex_get_counters_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x01200000)
#define gecko_cmd_l2cap_coc_send_connection_request_id                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x01430000)
#define gecko_cmd_l2cap_coc_send_connection_response_id               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x02430000)
#define gecko_cmd_l2cap_coc_send_le_flow_control_credit_id            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x03430000)
#define gecko_cmd_l2cap_coc_send_disconnection_request_id             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x04430000)
#define gecko_cmd_l2cap_coc_send_data_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x05430000)
#define gecko_cmd_cte_transmitter_enable_cte_response_id              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x00440000)
#define gecko_cmd_cte_transmitter_disable_cte_response_id             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x01440000)
#define gecko_cmd_cte_transmitter_start_connectionless_cte_id         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x02440000)
#define gecko_cmd_cte_transmitter_stop_connectionless_cte_id          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x03440000)
#define gecko_cmd_cte_transmitter_set_dtm_parameters_id               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x04440000)
#define gecko_cmd_cte_transmitter_clear_dtm_parameters_id             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x05440000)
#define gecko_cmd_cte_receiver_configure_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x00450000)
#define gecko_cmd_cte_receiver_start_iq_sampling_id                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x01450000)
#define gecko_cmd_cte_receiver_stop_iq_sampling_id                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x02450000)
#define gecko_cmd_cte_receiver_start_connectionless_iq_sampling_id    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x03450000)
#define gecko_cmd_cte_receiver_stop_connectionless_iq_sampling_id     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x04450000)
#define gecko_cmd_cte_receiver_set_dtm_parameters_id                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x05450000)
#define gecko_cmd_cte_receiver_clear_dtm_parameters_id                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x06450000)
#define gecko_cmd_user_message_to_target_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_cmd|0x00ff0000)

#define gecko_rsp_dfu_flash_set_address_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x01000000)
#define gecko_rsp_dfu_flash_upload_id                                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x02000000)
#define gecko_rsp_dfu_flash_upload_finish_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x03000000)
#define gecko_rsp_system_hello_id                                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x00010000)
#define gecko_rsp_system_get_bt_address_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x03010000)
#define gecko_rsp_system_set_bt_address_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x04010000)
#define gecko_rsp_system_set_tx_power_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0a010000)
#define gecko_rsp_system_get_random_data_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0b010000)
#define gecko_rsp_system_halt_id                                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0c010000)
#define gecko_rsp_system_set_device_name_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0d010000)
#define gecko_rsp_system_linklayer_configure_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0e010000)
#define gecko_rsp_system_get_counters_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0f010000)
#define gecko_rsp_system_set_identity_address_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x13010000)
#define gecko_rsp_le_gap_open_id                                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x00030000)
#define gecko_rsp_le_gap_set_mode_id                                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x01030000)
#define gecko_rsp_le_gap_discover_id                                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x02030000)
#define gecko_rsp_le_gap_end_procedure_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x03030000)
#define gecko_rsp_le_gap_set_adv_parameters_id                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x04030000)
#define gecko_rsp_le_gap_set_conn_parameters_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x05030000)
#define gecko_rsp_le_gap_set_scan_parameters_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x06030000)
#define gecko_rsp_le_gap_set_adv_data_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x07030000)
#define gecko_rsp_le_gap_set_adv_timeout_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x08030000)
#define gecko_rsp_le_gap_bt5_set_mode_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0a030000)
#define gecko_rsp_le_gap_bt5_set_adv_parameters_id                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0b030000)
#define gecko_rsp_le_gap_bt5_set_adv_data_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0c030000)
#define gecko_rsp_le_gap_set_privacy_mode_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0d030000)
#define gecko_rsp_le_gap_set_advertise_timing_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0e030000)
#define gecko_rsp_le_gap_set_advertise_channel_map_id                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0f030000)
#define gecko_rsp_le_gap_set_advertise_report_scan_request_id         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x10030000)
#define gecko_rsp_le_gap_set_advertise_phy_id                         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x11030000)
#define gecko_rsp_le_gap_set_advertise_configuration_id               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x12030000)
#define gecko_rsp_le_gap_clear_advertise_configuration_id             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x13030000)
#define gecko_rsp_le_gap_start_advertising_id                         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x14030000)
#define gecko_rsp_le_gap_stop_advertising_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x15030000)
#define gecko_rsp_le_gap_set_discovery_timing_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x16030000)
#define gecko_rsp_le_gap_set_discovery_type_id                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x17030000)
#define gecko_rsp_le_gap_start_discovery_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x18030000)
#define gecko_rsp_le_gap_set_data_channel_classification_id           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x19030000)
#define gecko_rsp_le_gap_connect_id                                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x1a030000)
#define gecko_rsp_le_gap_set_advertise_tx_power_id                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x1b030000)
#define gecko_rsp_le_gap_set_discovery_extended_scan_response_id      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x1c030000)
#define gecko_rsp_le_gap_start_periodic_advertising_id                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x1d030000)
#define gecko_rsp_le_gap_stop_periodic_advertising_id                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x1f030000)
#define gecko_rsp_le_gap_enable_whitelisting_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x21030000)
#define gecko_rsp_sync_open_id                                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x00420000)
#define gecko_rsp_sync_close_id                                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x01420000)
#define gecko_rsp_le_connection_set_parameters_id                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x00080000)
#define gecko_rsp_le_connection_get_rssi_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x01080000)
#define gecko_rsp_le_connection_disable_slave_latency_id              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x02080000)
#define gecko_rsp_le_connection_set_phy_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x03080000)
#define gecko_rsp_le_connection_close_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x04080000)
#define gecko_rsp_gatt_set_max_mtu_id                                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x00090000)
#define gecko_rsp_gatt_discover_primary_services_id                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x01090000)
#define gecko_rsp_gatt_discover_primary_services_by_uuid_id           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x02090000)
#define gecko_rsp_gatt_discover_characteristics_id                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x03090000)
#define gecko_rsp_gatt_discover_characteristics_by_uuid_id            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x04090000)
#define gecko_rsp_gatt_set_characteristic_notification_id             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x05090000)
#define gecko_rsp_gatt_discover_descriptors_id                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x06090000)
#define gecko_rsp_gatt_read_characteristic_value_id                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x07090000)
#define gecko_rsp_gatt_read_characteristic_value_by_uuid_id           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x08090000)
#define gecko_rsp_gatt_write_characteristic_value_id                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x09090000)
#define gecko_rsp_gatt_write_characteristic_value_without_response_id  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0a090000)
#define gecko_rsp_gatt_prepare_characteristic_value_write_id          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0b090000)
#define gecko_rsp_gatt_execute_characteristic_value_write_id          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0c090000)
#define gecko_rsp_gatt_send_characteristic_confirmation_id            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0d090000)
#define gecko_rsp_gatt_read_descriptor_value_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0e090000)
#define gecko_rsp_gatt_write_descriptor_value_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0f090000)
#define gecko_rsp_gatt_find_included_services_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x10090000)
#define gecko_rsp_gatt_read_multiple_characteristic_values_id         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x11090000)
#define gecko_rsp_gatt_read_characteristic_value_from_offset_id       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x12090000)
#define gecko_rsp_gatt_prepare_characteristic_value_reliable_write_id  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x13090000)
#define gecko_rsp_gatt_server_read_attribute_value_id                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x000a0000)
#define gecko_rsp_gatt_server_read_attribute_type_id                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x010a0000)
#define gecko_rsp_gatt_server_write_attribute_value_id                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x020a0000)
#define gecko_rsp_gatt_server_send_user_read_response_id              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x030a0000)
#define gecko_rsp_gatt_server_send_user_write_response_id             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x040a0000)
#define gecko_rsp_gatt_server_send_characteristic_notification_id     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x050a0000)
#define gecko_rsp_gatt_server_find_attribute_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x060a0000)
#define gecko_rsp_gatt_server_set_capabilities_id                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x080a0000)
#define gecko_rsp_hardware_set_soft_timer_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x000c0000)
#define gecko_rsp_hardware_get_time_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0b0c0000)
#define gecko_rsp_hardware_set_lazy_soft_timer_id                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0c0c0000)
#define gecko_rsp_flash_ps_erase_all_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x010d0000)
#define gecko_rsp_flash_ps_save_id                                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x020d0000)
#define gecko_rsp_flash_ps_load_id                                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x030d0000)
#define gecko_rsp_flash_ps_erase_id                                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x040d0000)
#define gecko_rsp_test_dtm_tx_id                                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x000e0000)
#define gecko_rsp_test_dtm_rx_id                                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x010e0000)
#define gecko_rsp_test_dtm_end_id                                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x020e0000)
#define gecko_rsp_sm_set_bondable_mode_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x000f0000)
#define gecko_rsp_sm_configure_id                                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x010f0000)
#define gecko_rsp_sm_store_bonding_configuration_id                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x020f0000)
#define gecko_rsp_sm_increase_security_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x040f0000)
#define gecko_rsp_sm_delete_bonding_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x060f0000)
#define gecko_rsp_sm_delete_bondings_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x070f0000)
#define gecko_rsp_sm_enter_passkey_id                                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x080f0000)
#define gecko_rsp_sm_passkey_confirm_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x090f0000)
#define gecko_rsp_sm_set_oob_data_id                                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0a0f0000)
#define gecko_rsp_sm_list_all_bondings_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0b0f0000)
#define gecko_rsp_sm_bonding_confirm_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0e0f0000)
#define gecko_rsp_sm_set_debug_mode_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x0f0f0000)
#define gecko_rsp_sm_set_passkey_id                                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x100f0000)
#define gecko_rsp_sm_use_sc_oob_id                                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x110f0000)
#define gecko_rsp_sm_set_sc_remote_oob_data_id                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x120f0000)
#define gecko_rsp_sm_add_to_whitelist_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x130f0000)
#define gecko_rsp_homekit_configure_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x00130000)
#define gecko_rsp_homekit_advertise_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x01130000)
#define gecko_rsp_homekit_delete_pairings_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x02130000)
#define gecko_rsp_homekit_check_authcp_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x03130000)
#define gecko_rsp_homekit_get_pairing_id_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x04130000)
#define gecko_rsp_homekit_send_write_response_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x05130000)
#define gecko_rsp_homekit_send_read_response_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x06130000)
#define gecko_rsp_homekit_gsn_action_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x07130000)
#define gecko_rsp_homekit_event_notification_id                       (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x08130000)
#define gecko_rsp_homekit_broadcast_action_id                         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x09130000)
#define gecko_rsp_coex_set_options_id                                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x00200000)
#define gecko_rsp_coex_get_counters_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x01200000)
#define gecko_rsp_l2cap_coc_send_connection_request_id                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x01430000)
#define gecko_rsp_l2cap_coc_send_connection_response_id               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x02430000)
#define gecko_rsp_l2cap_coc_send_le_flow_control_credit_id            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x03430000)
#define gecko_rsp_l2cap_coc_send_disconnection_request_id             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x04430000)
#define gecko_rsp_l2cap_coc_send_data_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x05430000)
#define gecko_rsp_cte_transmitter_enable_cte_response_id              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x00440000)
#define gecko_rsp_cte_transmitter_disable_cte_response_id             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x01440000)
#define gecko_rsp_cte_transmitter_start_connectionless_cte_id         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x02440000)
#define gecko_rsp_cte_transmitter_stop_connectionless_cte_id          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x03440000)
#define gecko_rsp_cte_transmitter_set_dtm_parameters_id               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x04440000)
#define gecko_rsp_cte_transmitter_clear_dtm_parameters_id             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x05440000)
#define gecko_rsp_cte_receiver_configure_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x00450000)
#define gecko_rsp_cte_receiver_start_iq_sampling_id                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x01450000)
#define gecko_rsp_cte_receiver_stop_iq_sampling_id                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x02450000)
#define gecko_rsp_cte_receiver_start_connectionless_iq_sampling_id    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x03450000)
#define gecko_rsp_cte_receiver_stop_connectionless_iq_sampling_id     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x04450000)
#define gecko_rsp_cte_receiver_set_dtm_parameters_id                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x05450000)
#define gecko_rsp_cte_receiver_clear_dtm_parameters_id                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x06450000)
#define gecko_rsp_user_message_to_target_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_rsp|0x00ff0000)

#define gecko_evt_dfu_boot_id                                         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x00000000)
#define gecko_evt_dfu_boot_failure_id                                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x01000000)
#define gecko_evt_system_boot_id                                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x00010000)
#define gecko_evt_system_external_signal_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x03010000)
#define gecko_evt_system_awake_id                                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x04010000)
#define gecko_evt_system_hardware_error_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x05010000)
#define gecko_evt_system_error_id                                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x06010000)
#define gecko_evt_le_gap_scan_response_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x00030000)
#define gecko_evt_le_gap_adv_timeout_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x01030000)
#define gecko_evt_le_gap_scan_request_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x02030000)
#define gecko_evt_le_gap_extended_scan_response_id                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x04030000)
#define gecko_evt_sync_opened_id                                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x00420000)
#define gecko_evt_sync_closed_id                                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x01420000)
#define gecko_evt_sync_data_id                                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x02420000)
#define gecko_evt_le_connection_opened_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x00080000)
#define gecko_evt_le_connection_closed_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x01080000)
#define gecko_evt_le_connection_parameters_id                         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x02080000)
#define gecko_evt_le_connection_rssi_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x03080000)
#define gecko_evt_le_connection_phy_status_id                         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x04080000)
#define gecko_evt_gatt_mtu_exchanged_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x00090000)
#define gecko_evt_gatt_service_id                                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x01090000)
#define gecko_evt_gatt_characteristic_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x02090000)
#define gecko_evt_gatt_descriptor_id                                  (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x03090000)
#define gecko_evt_gatt_characteristic_value_id                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x04090000)
#define gecko_evt_gatt_descriptor_value_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x05090000)
#define gecko_evt_gatt_procedure_completed_id                         (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x06090000)
#define gecko_evt_gatt_server_attribute_value_id                      (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x000a0000)
#define gecko_evt_gatt_server_user_read_request_id                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x010a0000)
#define gecko_evt_gatt_server_user_write_request_id                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x020a0000)
#define gecko_evt_gatt_server_characteristic_status_id                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x030a0000)
#define gecko_evt_gatt_server_execute_write_completed_id              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x040a0000)
#define gecko_evt_hardware_soft_timer_id                              (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x000c0000)
#define gecko_evt_test_dtm_completed_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x000e0000)
#define gecko_evt_sm_passkey_display_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x000f0000)
#define gecko_evt_sm_passkey_request_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x010f0000)
#define gecko_evt_sm_confirm_passkey_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x020f0000)
#define gecko_evt_sm_bonded_id                                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x030f0000)
#define gecko_evt_sm_bonding_failed_id                                (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x040f0000)
#define gecko_evt_sm_list_bonding_entry_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x050f0000)
#define gecko_evt_sm_list_all_bondings_complete_id                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x060f0000)
#define gecko_evt_sm_confirm_bonding_id                               (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x090f0000)
#define gecko_evt_homekit_setupcode_display_id                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x00130000)
#define gecko_evt_homekit_paired_id                                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x01130000)
#define gecko_evt_homekit_pair_verified_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x02130000)
#define gecko_evt_homekit_connection_opened_id                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x03130000)
#define gecko_evt_homekit_connection_closed_id                        (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x04130000)
#define gecko_evt_homekit_identify_id                                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x05130000)
#define gecko_evt_homekit_write_request_id                            (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x06130000)
#define gecko_evt_homekit_read_request_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x07130000)
#define gecko_evt_homekit_disconnection_required_id                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x08130000)
#define gecko_evt_homekit_pairing_removed_id                          (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x09130000)
#define gecko_evt_homekit_setuppayload_display_id                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x0a130000)
#define gecko_evt_l2cap_coc_connection_request_id                     (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x01430000)
#define gecko_evt_l2cap_coc_connection_response_id                    (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x02430000)
#define gecko_evt_l2cap_coc_le_flow_control_credit_id                 (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x03430000)
#define gecko_evt_l2cap_coc_channel_disconnected_id                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x04430000)
#define gecko_evt_l2cap_coc_data_id                                   (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x05430000)
#define gecko_evt_l2cap_command_rejected_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x06430000)
#define gecko_evt_cte_receiver_iq_report_id                           (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x00450000)
#define gecko_evt_user_message_to_host_id                             (((uint32)gecko_dev_type_gecko)|gecko_msg_type_evt|0x00ff0000)


PACKSTRUCT( struct gecko_msg_dfu_reset_cmd_t
{
    uint8               dfu;
});
PACKSTRUCT( struct gecko_msg_dfu_flash_set_address_cmd_t
{
    uint32              address;
});
PACKSTRUCT( struct gecko_msg_dfu_flash_set_address_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_dfu_flash_upload_cmd_t
{
    uint8array          data;
});
PACKSTRUCT( struct gecko_msg_dfu_flash_upload_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_dfu_flash_upload_finish_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_dfu_boot_evt_t
{
    uint32              version;
});
PACKSTRUCT( struct gecko_msg_dfu_boot_failure_evt_t
{
    uint16              reason;
});
PACKSTRUCT( struct gecko_msg_system_hello_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_system_reset_cmd_t
{
    uint8               dfu;
});
PACKSTRUCT( struct gecko_msg_system_get_bt_address_rsp_t
{
    bd_addr             address;
});
PACKSTRUCT( struct gecko_msg_system_set_bt_address_cmd_t
{
    bd_addr             address;
});
PACKSTRUCT( struct gecko_msg_system_set_bt_address_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_system_set_tx_power_cmd_t
{
    int16               power;
});
PACKSTRUCT( struct gecko_msg_system_set_tx_power_rsp_t
{
    int16               set_power;
});
PACKSTRUCT( struct gecko_msg_system_get_random_data_cmd_t
{
    uint8               length;
});
PACKSTRUCT( struct gecko_msg_system_get_random_data_rsp_t
{
    uint16              result;
    uint8array          data;
});
PACKSTRUCT( struct gecko_msg_system_halt_cmd_t
{
    uint8               halt;
});
PACKSTRUCT( struct gecko_msg_system_halt_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_system_set_device_name_cmd_t
{
    uint8               type;
    uint8array          name;
});
PACKSTRUCT( struct gecko_msg_system_set_device_name_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_system_linklayer_configure_cmd_t
{
    uint8               key;
    uint8array          data;
});
PACKSTRUCT( struct gecko_msg_system_linklayer_configure_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_system_get_counters_cmd_t
{
    uint8               reset;
});
PACKSTRUCT( struct gecko_msg_system_get_counters_rsp_t
{
    uint16              result;
    uint16              tx_packets;
    uint16              rx_packets;
    uint16              crc_errors;
    uint16              failures;
});
PACKSTRUCT( struct gecko_msg_system_set_identity_address_cmd_t
{
    bd_addr             address;
    uint8               type;
});
PACKSTRUCT( struct gecko_msg_system_set_identity_address_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_system_boot_evt_t
{
    uint16              major;
    uint16              minor;
    uint16              patch;
    uint16              build;
    uint32              bootloader;
    uint16              hw;
    uint32              hash;
});
PACKSTRUCT( struct gecko_msg_system_external_signal_evt_t
{
    uint32              extsignals;
});
PACKSTRUCT( struct gecko_msg_system_hardware_error_evt_t
{
    uint16              status;
});
PACKSTRUCT( struct gecko_msg_system_error_evt_t
{
    uint16              reason;
    uint8array          data;
});
PACKSTRUCT( struct gecko_msg_le_gap_open_cmd_t
{
    bd_addr             address;
    uint8               address_type;
});
PACKSTRUCT( struct gecko_msg_le_gap_open_rsp_t
{
    uint16              result;
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_mode_cmd_t
{
    uint8               discover;
    uint8               connect;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_mode_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_discover_cmd_t
{
    uint8               mode;
});
PACKSTRUCT( struct gecko_msg_le_gap_discover_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_end_procedure_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_adv_parameters_cmd_t
{
    uint16              interval_min;
    uint16              interval_max;
    uint8               channel_map;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_adv_parameters_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_conn_parameters_cmd_t
{
    uint16              min_interval;
    uint16              max_interval;
    uint16              latency;
    uint16              timeout;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_conn_parameters_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_scan_parameters_cmd_t
{
    uint16              scan_interval;
    uint16              scan_window;
    uint8               active;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_scan_parameters_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_adv_data_cmd_t
{
    uint8               scan_rsp;
    uint8array          adv_data;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_adv_data_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_adv_timeout_cmd_t
{
    uint8               maxevents;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_adv_timeout_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_bt5_set_mode_cmd_t
{
    uint8               handle;
    uint8               discover;
    uint8               connect;
    uint16              maxevents;
    uint8               address_type;
});
PACKSTRUCT( struct gecko_msg_le_gap_bt5_set_mode_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_bt5_set_adv_parameters_cmd_t
{
    uint8               handle;
    uint16              interval_min;
    uint16              interval_max;
    uint8               channel_map;
    uint8               report_scan;
});
PACKSTRUCT( struct gecko_msg_le_gap_bt5_set_adv_parameters_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_bt5_set_adv_data_cmd_t
{
    uint8               handle;
    uint8               scan_rsp;
    uint8array          adv_data;
});
PACKSTRUCT( struct gecko_msg_le_gap_bt5_set_adv_data_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_privacy_mode_cmd_t
{
    uint8               privacy;
    uint8               interval;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_privacy_mode_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_advertise_timing_cmd_t
{
    uint8               handle;
    uint32              interval_min;
    uint32              interval_max;
    uint16              duration;
    uint8               maxevents;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_advertise_timing_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_advertise_channel_map_cmd_t
{
    uint8               handle;
    uint8               channel_map;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_advertise_channel_map_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_advertise_report_scan_request_cmd_t
{
    uint8               handle;
    uint8               report_scan_req;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_advertise_report_scan_request_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_advertise_phy_cmd_t
{
    uint8               handle;
    uint8               primary_phy;
    uint8               secondary_phy;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_advertise_phy_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_advertise_configuration_cmd_t
{
    uint8               handle;
    uint32              configurations;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_advertise_configuration_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_clear_advertise_configuration_cmd_t
{
    uint8               handle;
    uint32              configurations;
});
PACKSTRUCT( struct gecko_msg_le_gap_clear_advertise_configuration_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_start_advertising_cmd_t
{
    uint8               handle;
    uint8               discover;
    uint8               connect;
});
PACKSTRUCT( struct gecko_msg_le_gap_start_advertising_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_stop_advertising_cmd_t
{
    uint8               handle;
});
PACKSTRUCT( struct gecko_msg_le_gap_stop_advertising_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_discovery_timing_cmd_t
{
    uint8               phys;
    uint16              scan_interval;
    uint16              scan_window;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_discovery_timing_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_discovery_type_cmd_t
{
    uint8               phys;
    uint8               scan_type;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_discovery_type_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_start_discovery_cmd_t
{
    uint8               scanning_phy;
    uint8               mode;
});
PACKSTRUCT( struct gecko_msg_le_gap_start_discovery_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_data_channel_classification_cmd_t
{
    uint8array          channel_map;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_data_channel_classification_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_connect_cmd_t
{
    bd_addr             address;
    uint8               address_type;
    uint8               initiating_phy;
});
PACKSTRUCT( struct gecko_msg_le_gap_connect_rsp_t
{
    uint16              result;
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_advertise_tx_power_cmd_t
{
    uint8               handle;
    int16               power;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_advertise_tx_power_rsp_t
{
    uint16              result;
    int16               set_power;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_discovery_extended_scan_response_cmd_t
{
    uint8               enable;
});
PACKSTRUCT( struct gecko_msg_le_gap_set_discovery_extended_scan_response_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_start_periodic_advertising_cmd_t
{
    uint8               handle;
    uint16              interval_min;
    uint16              interval_max;
    uint32              flags;
});
PACKSTRUCT( struct gecko_msg_le_gap_start_periodic_advertising_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_stop_periodic_advertising_cmd_t
{
    uint8               handle;
});
PACKSTRUCT( struct gecko_msg_le_gap_stop_periodic_advertising_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_enable_whitelisting_cmd_t
{
    uint8               enable;
});
PACKSTRUCT( struct gecko_msg_le_gap_enable_whitelisting_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_gap_scan_response_evt_t
{
    int8                rssi;
    uint8               packet_type;
    bd_addr             address;
    uint8               address_type;
    uint8               bonding;
    uint8array          data;
});
PACKSTRUCT( struct gecko_msg_le_gap_adv_timeout_evt_t
{
    uint8               handle;
});
PACKSTRUCT( struct gecko_msg_le_gap_scan_request_evt_t
{
    uint8               handle;
    bd_addr             address;
    uint8               address_type;
    uint8               bonding;
});
PACKSTRUCT( struct gecko_msg_le_gap_extended_scan_response_evt_t
{
    uint8               packet_type;
    bd_addr             address;
    uint8               address_type;
    uint8               bonding;
    uint8               primary_phy;
    uint8               secondary_phy;
    uint8               adv_sid;
    int8                tx_power;
    int8                rssi;
    uint8               channel;
    uint16              periodic_interval;
    uint8array          data;
});
PACKSTRUCT( struct gecko_msg_sync_open_cmd_t
{
    uint8               adv_sid;
    uint16              skip;
    uint16              timeout;
    bd_addr             address;
    uint8               address_type;
});
PACKSTRUCT( struct gecko_msg_sync_open_rsp_t
{
    uint16              result;
    uint8               sync;
});
PACKSTRUCT( struct gecko_msg_sync_close_cmd_t
{
    uint8               sync;
});
PACKSTRUCT( struct gecko_msg_sync_close_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sync_opened_evt_t
{
    uint8               sync;
    uint8               adv_sid;
    bd_addr             address;
    uint8               address_type;
    uint8               adv_phy;
    uint16              adv_interval;
    uint16              clock_accuracy;
});
PACKSTRUCT( struct gecko_msg_sync_closed_evt_t
{
    uint16              reason;
    uint8               sync;
});
PACKSTRUCT( struct gecko_msg_sync_data_evt_t
{
    uint8               sync;
    int8                tx_power;
    int8                rssi;
    uint8               data_status;
    uint8array          data;
});
PACKSTRUCT( struct gecko_msg_le_connection_set_parameters_cmd_t
{
    uint8               connection;
    uint16              min_interval;
    uint16              max_interval;
    uint16              latency;
    uint16              timeout;
});
PACKSTRUCT( struct gecko_msg_le_connection_set_parameters_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_connection_get_rssi_cmd_t
{
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_le_connection_get_rssi_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_connection_disable_slave_latency_cmd_t
{
    uint8               connection;
    uint8               disable;
});
PACKSTRUCT( struct gecko_msg_le_connection_disable_slave_latency_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_connection_set_phy_cmd_t
{
    uint8               connection;
    uint8               phy;
});
PACKSTRUCT( struct gecko_msg_le_connection_set_phy_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_connection_close_cmd_t
{
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_le_connection_close_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_le_connection_opened_evt_t
{
    bd_addr             address;
    uint8               address_type;
    uint8               master;
    uint8               connection;
    uint8               bonding;
    uint8               advertiser;
});
PACKSTRUCT( struct gecko_msg_le_connection_closed_evt_t
{
    uint16              reason;
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_le_connection_parameters_evt_t
{
    uint8               connection;
    uint16              interval;
    uint16              latency;
    uint16              timeout;
    uint8               security_mode;
    uint16              txsize;
});
PACKSTRUCT( struct gecko_msg_le_connection_rssi_evt_t
{
    uint8               connection;
    uint8               status;
    int8                rssi;
});
PACKSTRUCT( struct gecko_msg_le_connection_phy_status_evt_t
{
    uint8               connection;
    uint8               phy;
});
PACKSTRUCT( struct gecko_msg_gatt_set_max_mtu_cmd_t
{
    uint16              max_mtu;
});
PACKSTRUCT( struct gecko_msg_gatt_set_max_mtu_rsp_t
{
    uint16              result;
    uint16              max_mtu;
});
PACKSTRUCT( struct gecko_msg_gatt_discover_primary_services_cmd_t
{
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_gatt_discover_primary_services_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_discover_primary_services_by_uuid_cmd_t
{
    uint8               connection;
    uint8array          uuid;
});
PACKSTRUCT( struct gecko_msg_gatt_discover_primary_services_by_uuid_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_discover_characteristics_cmd_t
{
    uint8               connection;
    uint32              service;
});
PACKSTRUCT( struct gecko_msg_gatt_discover_characteristics_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_discover_characteristics_by_uuid_cmd_t
{
    uint8               connection;
    uint32              service;
    uint8array          uuid;
});
PACKSTRUCT( struct gecko_msg_gatt_discover_characteristics_by_uuid_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_set_characteristic_notification_cmd_t
{
    uint8               connection;
    uint16              characteristic;
    uint8               flags;
});
PACKSTRUCT( struct gecko_msg_gatt_set_characteristic_notification_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_discover_descriptors_cmd_t
{
    uint8               connection;
    uint16              characteristic;
});
PACKSTRUCT( struct gecko_msg_gatt_discover_descriptors_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_read_characteristic_value_cmd_t
{
    uint8               connection;
    uint16              characteristic;
});
PACKSTRUCT( struct gecko_msg_gatt_read_characteristic_value_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_read_characteristic_value_by_uuid_cmd_t
{
    uint8               connection;
    uint32              service;
    uint8array          uuid;
});
PACKSTRUCT( struct gecko_msg_gatt_read_characteristic_value_by_uuid_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_write_characteristic_value_cmd_t
{
    uint8               connection;
    uint16              characteristic;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_write_characteristic_value_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_write_characteristic_value_without_response_cmd_t
{
    uint8               connection;
    uint16              characteristic;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_write_characteristic_value_without_response_rsp_t
{
    uint16              result;
    uint16              sent_len;
});
PACKSTRUCT( struct gecko_msg_gatt_prepare_characteristic_value_write_cmd_t
{
    uint8               connection;
    uint16              characteristic;
    uint16              offset;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_prepare_characteristic_value_write_rsp_t
{
    uint16              result;
    uint16              sent_len;
});
PACKSTRUCT( struct gecko_msg_gatt_execute_characteristic_value_write_cmd_t
{
    uint8               connection;
    uint8               flags;
});
PACKSTRUCT( struct gecko_msg_gatt_execute_characteristic_value_write_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_send_characteristic_confirmation_cmd_t
{
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_gatt_send_characteristic_confirmation_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_read_descriptor_value_cmd_t
{
    uint8               connection;
    uint16              descriptor;
});
PACKSTRUCT( struct gecko_msg_gatt_read_descriptor_value_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_write_descriptor_value_cmd_t
{
    uint8               connection;
    uint16              descriptor;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_write_descriptor_value_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_find_included_services_cmd_t
{
    uint8               connection;
    uint32              service;
});
PACKSTRUCT( struct gecko_msg_gatt_find_included_services_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_read_multiple_characteristic_values_cmd_t
{
    uint8               connection;
    uint8array          characteristic_list;
});
PACKSTRUCT( struct gecko_msg_gatt_read_multiple_characteristic_values_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_read_characteristic_value_from_offset_cmd_t
{
    uint8               connection;
    uint16              characteristic;
    uint16              offset;
    uint16              maxlen;
});
PACKSTRUCT( struct gecko_msg_gatt_read_characteristic_value_from_offset_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_prepare_characteristic_value_reliable_write_cmd_t
{
    uint8               connection;
    uint16              characteristic;
    uint16              offset;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_prepare_characteristic_value_reliable_write_rsp_t
{
    uint16              result;
    uint16              sent_len;
});
PACKSTRUCT( struct gecko_msg_gatt_mtu_exchanged_evt_t
{
    uint8               connection;
    uint16              mtu;
});
PACKSTRUCT( struct gecko_msg_gatt_service_evt_t
{
    uint8               connection;
    uint32              service;
    uint8array          uuid;
});
PACKSTRUCT( struct gecko_msg_gatt_characteristic_evt_t
{
    uint8               connection;
    uint16              characteristic;
    uint8               properties;
    uint8array          uuid;
});
PACKSTRUCT( struct gecko_msg_gatt_descriptor_evt_t
{
    uint8               connection;
    uint16              descriptor;
    uint8array          uuid;
});
PACKSTRUCT( struct gecko_msg_gatt_characteristic_value_evt_t
{
    uint8               connection;
    uint16              characteristic;
    uint8               att_opcode;
    uint16              offset;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_descriptor_value_evt_t
{
    uint8               connection;
    uint16              descriptor;
    uint16              offset;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_procedure_completed_evt_t
{
    uint8               connection;
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_server_read_attribute_value_cmd_t
{
    uint16              attribute;
    uint16              offset;
});
PACKSTRUCT( struct gecko_msg_gatt_server_read_attribute_value_rsp_t
{
    uint16              result;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_server_read_attribute_type_cmd_t
{
    uint16              attribute;
});
PACKSTRUCT( struct gecko_msg_gatt_server_read_attribute_type_rsp_t
{
    uint16              result;
    uint8array          type;
});
PACKSTRUCT( struct gecko_msg_gatt_server_write_attribute_value_cmd_t
{
    uint16              attribute;
    uint16              offset;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_server_write_attribute_value_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_server_send_user_read_response_cmd_t
{
    uint8               connection;
    uint16              characteristic;
    uint8               att_errorcode;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_server_send_user_read_response_rsp_t
{
    uint16              result;
    uint16              sent_len;
});
PACKSTRUCT( struct gecko_msg_gatt_server_send_user_write_response_cmd_t
{
    uint8               connection;
    uint16              characteristic;
    uint8               att_errorcode;
});
PACKSTRUCT( struct gecko_msg_gatt_server_send_user_write_response_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_server_send_characteristic_notification_cmd_t
{
    uint8               connection;
    uint16              characteristic;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_server_send_characteristic_notification_rsp_t
{
    uint16              result;
    uint16              sent_len;
});
PACKSTRUCT( struct gecko_msg_gatt_server_find_attribute_cmd_t
{
    uint16              start;
    uint8array          type;
});
PACKSTRUCT( struct gecko_msg_gatt_server_find_attribute_rsp_t
{
    uint16              result;
    uint16              attribute;
});
PACKSTRUCT( struct gecko_msg_gatt_server_set_capabilities_cmd_t
{
    uint32              caps;
    uint32              reserved;
});
PACKSTRUCT( struct gecko_msg_gatt_server_set_capabilities_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_gatt_server_attribute_value_evt_t
{
    uint8               connection;
    uint16              attribute;
    uint8               att_opcode;
    uint16              offset;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_server_user_read_request_evt_t
{
    uint8               connection;
    uint16              characteristic;
    uint8               att_opcode;
    uint16              offset;
});
PACKSTRUCT( struct gecko_msg_gatt_server_user_write_request_evt_t
{
    uint8               connection;
    uint16              characteristic;
    uint8               att_opcode;
    uint16              offset;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_gatt_server_characteristic_status_evt_t
{
    uint8               connection;
    uint16              characteristic;
    uint8               status_flags;
    uint16              client_config_flags;
});
PACKSTRUCT( struct gecko_msg_gatt_server_execute_write_completed_evt_t
{
    uint8               connection;
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_hardware_set_soft_timer_cmd_t
{
    uint32              time;
    uint8               handle;
    uint8               single_shot;
});
PACKSTRUCT( struct gecko_msg_hardware_set_soft_timer_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_hardware_get_time_rsp_t
{
    uint32              seconds;
    uint16              ticks;
});
PACKSTRUCT( struct gecko_msg_hardware_set_lazy_soft_timer_cmd_t
{
    uint32              time;
    uint32              slack;
    uint8               handle;
    uint8               single_shot;
});
PACKSTRUCT( struct gecko_msg_hardware_set_lazy_soft_timer_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_hardware_soft_timer_evt_t
{
    uint8               handle;
});
PACKSTRUCT( struct gecko_msg_flash_ps_erase_all_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_flash_ps_save_cmd_t
{
    uint16              key;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_flash_ps_save_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_flash_ps_load_cmd_t
{
    uint16              key;
});
PACKSTRUCT( struct gecko_msg_flash_ps_load_rsp_t
{
    uint16              result;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_flash_ps_erase_cmd_t
{
    uint16              key;
});
PACKSTRUCT( struct gecko_msg_flash_ps_erase_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_test_dtm_tx_cmd_t
{
    uint8               packet_type;
    uint8               length;
    uint8               channel;
    uint8               phy;
});
PACKSTRUCT( struct gecko_msg_test_dtm_tx_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_test_dtm_rx_cmd_t
{
    uint8               channel;
    uint8               phy;
});
PACKSTRUCT( struct gecko_msg_test_dtm_rx_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_test_dtm_end_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_test_dtm_completed_evt_t
{
    uint16              result;
    uint16              number_of_packets;
});
PACKSTRUCT( struct gecko_msg_sm_set_bondable_mode_cmd_t
{
    uint8               bondable;
});
PACKSTRUCT( struct gecko_msg_sm_set_bondable_mode_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_configure_cmd_t
{
    uint8               flags;
    uint8               io_capabilities;
});
PACKSTRUCT( struct gecko_msg_sm_configure_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_store_bonding_configuration_cmd_t
{
    uint8               max_bonding_count;
    uint8               policy_flags;
});
PACKSTRUCT( struct gecko_msg_sm_store_bonding_configuration_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_increase_security_cmd_t
{
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_sm_increase_security_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_delete_bonding_cmd_t
{
    uint8               bonding;
});
PACKSTRUCT( struct gecko_msg_sm_delete_bonding_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_delete_bondings_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_enter_passkey_cmd_t
{
    uint8               connection;
    int32               passkey;
});
PACKSTRUCT( struct gecko_msg_sm_enter_passkey_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_passkey_confirm_cmd_t
{
    uint8               connection;
    uint8               confirm;
});
PACKSTRUCT( struct gecko_msg_sm_passkey_confirm_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_set_oob_data_cmd_t
{
    uint8array          oob_data;
});
PACKSTRUCT( struct gecko_msg_sm_set_oob_data_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_list_all_bondings_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_bonding_confirm_cmd_t
{
    uint8               connection;
    uint8               confirm;
});
PACKSTRUCT( struct gecko_msg_sm_bonding_confirm_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_set_debug_mode_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_set_passkey_cmd_t
{
    int32               passkey;
});
PACKSTRUCT( struct gecko_msg_sm_set_passkey_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_use_sc_oob_cmd_t
{
    uint8               enable;
});
PACKSTRUCT( struct gecko_msg_sm_use_sc_oob_rsp_t
{
    uint16              result;
    uint8array          oob_data;
});
PACKSTRUCT( struct gecko_msg_sm_set_sc_remote_oob_data_cmd_t
{
    uint8array          oob_data;
});
PACKSTRUCT( struct gecko_msg_sm_set_sc_remote_oob_data_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_add_to_whitelist_cmd_t
{
    bd_addr             address;
    uint8               address_type;
});
PACKSTRUCT( struct gecko_msg_sm_add_to_whitelist_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_sm_passkey_display_evt_t
{
    uint8               connection;
    uint32              passkey;
});
PACKSTRUCT( struct gecko_msg_sm_passkey_request_evt_t
{
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_sm_confirm_passkey_evt_t
{
    uint8               connection;
    uint32              passkey;
});
PACKSTRUCT( struct gecko_msg_sm_bonded_evt_t
{
    uint8               connection;
    uint8               bonding;
});
PACKSTRUCT( struct gecko_msg_sm_bonding_failed_evt_t
{
    uint8               connection;
    uint16              reason;
});
PACKSTRUCT( struct gecko_msg_sm_list_bonding_entry_evt_t
{
    uint8               bonding;
    bd_addr             address;
    uint8               address_type;
});
PACKSTRUCT( struct gecko_msg_sm_confirm_bonding_evt_t
{
    uint8               connection;
    int8                bonding_handle;
});
PACKSTRUCT( struct gecko_msg_homekit_configure_cmd_t
{
    uint8               i2c_address;
    uint8               support_display;
    uint8               hap_attribute_features;
    uint16              category;
    uint8               configuration_number;
    uint16              fast_advert_interval;
    uint16              fast_advert_timeout;
    uint32              flag;
    uint16              broadcast_advert_timeout;
    uint8array          model_name;
});
PACKSTRUCT( struct gecko_msg_homekit_configure_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_homekit_advertise_cmd_t
{
    uint8               enable;
    uint16              interval_min;
    uint16              interval_max;
    uint8               channel_map;
});
PACKSTRUCT( struct gecko_msg_homekit_advertise_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_homekit_delete_pairings_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_homekit_check_authcp_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_homekit_get_pairing_id_cmd_t
{
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_homekit_get_pairing_id_rsp_t
{
    uint16              result;
    uint8array          pairing_id;
});
PACKSTRUCT( struct gecko_msg_homekit_send_write_response_cmd_t
{
    uint8               connection;
    uint16              characteristic;
    uint8               status_code;
});
PACKSTRUCT( struct gecko_msg_homekit_send_write_response_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_homekit_send_read_response_cmd_t
{
    uint8               connection;
    uint16              characteristic;
    uint8               status_code;
    uint16              attribute_size;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_homekit_send_read_response_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_homekit_gsn_action_cmd_t
{
    uint8               action;
});
PACKSTRUCT( struct gecko_msg_homekit_gsn_action_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_homekit_event_notification_cmd_t
{
    uint8               connection;
    uint16              characteristic;
    uint8               change_originator;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_homekit_event_notification_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_homekit_broadcast_action_cmd_t
{
    uint8               action;
    uint8array          params;
});
PACKSTRUCT( struct gecko_msg_homekit_broadcast_action_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_homekit_setupcode_display_evt_t
{
    uint8               connection;
    uint8array          setupcode;
});
PACKSTRUCT( struct gecko_msg_homekit_paired_evt_t
{
    uint8               connection;
    uint16              reason;
});
PACKSTRUCT( struct gecko_msg_homekit_pair_verified_evt_t
{
    uint8               connection;
    uint16              reason;
});
PACKSTRUCT( struct gecko_msg_homekit_connection_opened_evt_t
{
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_homekit_connection_closed_evt_t
{
    uint8               connection;
    uint16              reason;
});
PACKSTRUCT( struct gecko_msg_homekit_identify_evt_t
{
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_homekit_write_request_evt_t
{
    uint8               connection;
    uint16              characteristic;
    uint16              chr_value_size;
    uint16              authorization_size;
    uint16              value_offset;
    uint8array          value;
});
PACKSTRUCT( struct gecko_msg_homekit_read_request_evt_t
{
    uint8               connection;
    uint16              characteristic;
    uint16              offset;
});
PACKSTRUCT( struct gecko_msg_homekit_disconnection_required_evt_t
{
    uint8               connection;
    uint16              reason;
});
PACKSTRUCT( struct gecko_msg_homekit_pairing_removed_evt_t
{
    uint8               connection;
    uint16              remaining_pairings;
    uint8array          pairing_id;
});
PACKSTRUCT( struct gecko_msg_homekit_setuppayload_display_evt_t
{
    uint8               connection;
    uint8array          setuppayload;
});
PACKSTRUCT( struct gecko_msg_coex_set_options_cmd_t
{
    uint32              mask;
    uint32              options;
});
PACKSTRUCT( struct gecko_msg_coex_set_options_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_coex_get_counters_cmd_t
{
    uint8               reset;
});
PACKSTRUCT( struct gecko_msg_coex_get_counters_rsp_t
{
    uint16              result;
    uint8array          counters;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_send_connection_request_cmd_t
{
    uint8               connection;
    uint16              le_psm;
    uint16              mtu;
    uint16              mps;
    uint16              initial_credit;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_send_connection_request_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_send_connection_response_cmd_t
{
    uint8               connection;
    uint16              cid;
    uint16              mtu;
    uint16              mps;
    uint16              initial_credit;
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_send_connection_response_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_send_le_flow_control_credit_cmd_t
{
    uint8               connection;
    uint16              cid;
    uint16              credits;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_send_le_flow_control_credit_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_send_disconnection_request_cmd_t
{
    uint8               connection;
    uint16              cid;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_send_disconnection_request_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_send_data_cmd_t
{
    uint8               connection;
    uint16              cid;
    uint8array          data;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_send_data_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_connection_request_evt_t
{
    uint8               connection;
    uint16              le_psm;
    uint16              source_cid;
    uint16              mtu;
    uint16              mps;
    uint16              initial_credit;
    uint8               flags;
    uint8               encryption_key_size;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_connection_response_evt_t
{
    uint8               connection;
    uint16              destination_cid;
    uint16              mtu;
    uint16              mps;
    uint16              initial_credit;
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_le_flow_control_credit_evt_t
{
    uint8               connection;
    uint16              cid;
    uint16              credits;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_channel_disconnected_evt_t
{
    uint8               connection;
    uint16              cid;
    uint16              reason;
});
PACKSTRUCT( struct gecko_msg_l2cap_coc_data_evt_t
{
    uint8               connection;
    uint16              cid;
    uint8array          data;
});
PACKSTRUCT( struct gecko_msg_l2cap_command_rejected_evt_t
{
    uint8               connection;
    uint8               code;
    uint16              reason;
});
PACKSTRUCT( struct gecko_msg_cte_transmitter_enable_cte_response_cmd_t
{
    uint8               connection;
    uint8               cte_types;
    uint8array          switching_pattern;
});
PACKSTRUCT( struct gecko_msg_cte_transmitter_enable_cte_response_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_transmitter_disable_cte_response_cmd_t
{
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_cte_transmitter_disable_cte_response_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_transmitter_start_connectionless_cte_cmd_t
{
    uint8               adv;
    uint8               cte_length;
    uint8               cte_type;
    uint8               cte_count;
    uint8array          switching_pattern;
});
PACKSTRUCT( struct gecko_msg_cte_transmitter_start_connectionless_cte_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_transmitter_stop_connectionless_cte_cmd_t
{
    uint8               adv;
});
PACKSTRUCT( struct gecko_msg_cte_transmitter_stop_connectionless_cte_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_transmitter_set_dtm_parameters_cmd_t
{
    uint8               cte_length;
    uint8               cte_type;
    uint8array          switching_pattern;
});
PACKSTRUCT( struct gecko_msg_cte_transmitter_set_dtm_parameters_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_transmitter_clear_dtm_parameters_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_configure_cmd_t
{
    uint8               flags;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_configure_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_start_iq_sampling_cmd_t
{
    uint8               connection;
    uint16              interval;
    uint8               cte_length;
    uint8               cte_type;
    uint8               slot_durations;
    uint8array          switching_pattern;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_start_iq_sampling_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_stop_iq_sampling_cmd_t
{
    uint8               connection;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_stop_iq_sampling_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_start_connectionless_iq_sampling_cmd_t
{
    uint8               sync;
    uint8               slot_durations;
    uint8               cte_count;
    uint8array          switching_pattern;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_start_connectionless_iq_sampling_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_stop_connectionless_iq_sampling_cmd_t
{
    uint8               sync;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_stop_connectionless_iq_sampling_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_set_dtm_parameters_cmd_t
{
    uint8               cte_length;
    uint8               cte_type;
    uint8               slot_durations;
    uint8array          switching_pattern;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_set_dtm_parameters_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_clear_dtm_parameters_rsp_t
{
    uint16              result;
});
PACKSTRUCT( struct gecko_msg_cte_receiver_iq_report_evt_t
{
    uint16              status;
    uint8               packet_type;
    uint8               handle;
    int16               rssi;
    uint8               channel;
    uint8array          samples;
});
PACKSTRUCT( struct gecko_msg_user_message_to_target_cmd_t
{
    uint8array          data;
});
PACKSTRUCT( struct gecko_msg_user_message_to_target_rsp_t
{
    uint16              result;
    uint8array          data;
});
PACKSTRUCT( struct gecko_msg_user_message_to_host_evt_t
{
    uint8array          data;
});


PACKSTRUCT( struct gecko_cmd_packet
{
    uint32   header;

union{
    uint8 handle;
    struct gecko_msg_dfu_reset_cmd_t                             cmd_dfu_reset;
    struct gecko_msg_dfu_flash_set_address_cmd_t                 cmd_dfu_flash_set_address;
    struct gecko_msg_dfu_flash_set_address_rsp_t                 rsp_dfu_flash_set_address;
    struct gecko_msg_dfu_flash_upload_cmd_t                      cmd_dfu_flash_upload;
    struct gecko_msg_dfu_flash_upload_rsp_t                      rsp_dfu_flash_upload;
    struct gecko_msg_dfu_flash_upload_finish_rsp_t               rsp_dfu_flash_upload_finish;
    struct gecko_msg_dfu_boot_evt_t                              evt_dfu_boot;
    struct gecko_msg_dfu_boot_failure_evt_t                      evt_dfu_boot_failure;
    struct gecko_msg_system_hello_rsp_t                          rsp_system_hello;
    struct gecko_msg_system_reset_cmd_t                          cmd_system_reset;
    struct gecko_msg_system_get_bt_address_rsp_t                 rsp_system_get_bt_address;
    struct gecko_msg_system_set_bt_address_cmd_t                 cmd_system_set_bt_address;
    struct gecko_msg_system_set_bt_address_rsp_t                 rsp_system_set_bt_address;
    struct gecko_msg_system_set_tx_power_cmd_t                   cmd_system_set_tx_power;
    struct gecko_msg_system_set_tx_power_rsp_t                   rsp_system_set_tx_power;
    struct gecko_msg_system_get_random_data_cmd_t                cmd_system_get_random_data;
    struct gecko_msg_system_get_random_data_rsp_t                rsp_system_get_random_data;
    struct gecko_msg_system_halt_cmd_t                           cmd_system_halt;
    struct gecko_msg_system_halt_rsp_t                           rsp_system_halt;
    struct gecko_msg_system_set_device_name_cmd_t                cmd_system_set_device_name;
    struct gecko_msg_system_set_device_name_rsp_t                rsp_system_set_device_name;
    struct gecko_msg_system_linklayer_configure_cmd_t            cmd_system_linklayer_configure;
    struct gecko_msg_system_linklayer_configure_rsp_t            rsp_system_linklayer_configure;
    struct gecko_msg_system_get_counters_cmd_t                   cmd_system_get_counters;
    struct gecko_msg_system_get_counters_rsp_t                   rsp_system_get_counters;
    struct gecko_msg_system_set_identity_address_cmd_t           cmd_system_set_identity_address;
    struct gecko_msg_system_set_identity_address_rsp_t           rsp_system_set_identity_address;
    struct gecko_msg_system_boot_evt_t                           evt_system_boot;
    struct gecko_msg_system_external_signal_evt_t                evt_system_external_signal;
    struct gecko_msg_system_hardware_error_evt_t                 evt_system_hardware_error;
    struct gecko_msg_system_error_evt_t                          evt_system_error;
    struct gecko_msg_le_gap_open_cmd_t                           cmd_le_gap_open;
    struct gecko_msg_le_gap_open_rsp_t                           rsp_le_gap_open;
    struct gecko_msg_le_gap_set_mode_cmd_t                       cmd_le_gap_set_mode;
    struct gecko_msg_le_gap_set_mode_rsp_t                       rsp_le_gap_set_mode;
    struct gecko_msg_le_gap_discover_cmd_t                       cmd_le_gap_discover;
    struct gecko_msg_le_gap_discover_rsp_t                       rsp_le_gap_discover;
    struct gecko_msg_le_gap_end_procedure_rsp_t                  rsp_le_gap_end_procedure;
    struct gecko_msg_le_gap_set_adv_parameters_cmd_t             cmd_le_gap_set_adv_parameters;
    struct gecko_msg_le_gap_set_adv_parameters_rsp_t             rsp_le_gap_set_adv_parameters;
    struct gecko_msg_le_gap_set_conn_parameters_cmd_t            cmd_le_gap_set_conn_parameters;
    struct gecko_msg_le_gap_set_conn_parameters_rsp_t            rsp_le_gap_set_conn_parameters;
    struct gecko_msg_le_gap_set_scan_parameters_cmd_t            cmd_le_gap_set_scan_parameters;
    struct gecko_msg_le_gap_set_scan_parameters_rsp_t            rsp_le_gap_set_scan_parameters;
    struct gecko_msg_le_gap_set_adv_data_cmd_t                   cmd_le_gap_set_adv_data;
    struct gecko_msg_le_gap_set_adv_data_rsp_t                   rsp_le_gap_set_adv_data;
    struct gecko_msg_le_gap_set_adv_timeout_cmd_t                cmd_le_gap_set_adv_timeout;
    struct gecko_msg_le_gap_set_adv_timeout_rsp_t                rsp_le_gap_set_adv_timeout;
    struct gecko_msg_le_gap_bt5_set_mode_cmd_t                   cmd_le_gap_bt5_set_mode;
    struct gecko_msg_le_gap_bt5_set_mode_rsp_t                   rsp_le_gap_bt5_set_mode;
    struct gecko_msg_le_gap_bt5_set_adv_parameters_cmd_t         cmd_le_gap_bt5_set_adv_parameters;
    struct gecko_msg_le_gap_bt5_set_adv_parameters_rsp_t         rsp_le_gap_bt5_set_adv_parameters;
    struct gecko_msg_le_gap_bt5_set_adv_data_cmd_t               cmd_le_gap_bt5_set_adv_data;
    struct gecko_msg_le_gap_bt5_set_adv_data_rsp_t               rsp_le_gap_bt5_set_adv_data;
    struct gecko_msg_le_gap_set_privacy_mode_cmd_t               cmd_le_gap_set_privacy_mode;
    struct gecko_msg_le_gap_set_privacy_mode_rsp_t               rsp_le_gap_set_privacy_mode;
    struct gecko_msg_le_gap_set_advertise_timing_cmd_t           cmd_le_gap_set_advertise_timing;
    struct gecko_msg_le_gap_set_advertise_timing_rsp_t           rsp_le_gap_set_advertise_timing;
    struct gecko_msg_le_gap_set_advertise_channel_map_cmd_t      cmd_le_gap_set_advertise_channel_map;
    struct gecko_msg_le_gap_set_advertise_channel_map_rsp_t      rsp_le_gap_set_advertise_channel_map;
    struct gecko_msg_le_gap_set_advertise_report_scan_request_cmd_t cmd_le_gap_set_advertise_report_scan_request;
    struct gecko_msg_le_gap_set_advertise_report_scan_request_rsp_t rsp_le_gap_set_advertise_report_scan_request;
    struct gecko_msg_le_gap_set_advertise_phy_cmd_t              cmd_le_gap_set_advertise_phy;
    struct gecko_msg_le_gap_set_advertise_phy_rsp_t              rsp_le_gap_set_advertise_phy;
    struct gecko_msg_le_gap_set_advertise_configuration_cmd_t    cmd_le_gap_set_advertise_configuration;
    struct gecko_msg_le_gap_set_advertise_configuration_rsp_t    rsp_le_gap_set_advertise_configuration;
    struct gecko_msg_le_gap_clear_advertise_configuration_cmd_t  cmd_le_gap_clear_advertise_configuration;
    struct gecko_msg_le_gap_clear_advertise_configuration_rsp_t  rsp_le_gap_clear_advertise_configuration;
    struct gecko_msg_le_gap_start_advertising_cmd_t              cmd_le_gap_start_advertising;
    struct gecko_msg_le_gap_start_advertising_rsp_t              rsp_le_gap_start_advertising;
    struct gecko_msg_le_gap_stop_advertising_cmd_t               cmd_le_gap_stop_advertising;
    struct gecko_msg_le_gap_stop_advertising_rsp_t               rsp_le_gap_stop_advertising;
    struct gecko_msg_le_gap_set_discovery_timing_cmd_t           cmd_le_gap_set_discovery_timing;
    struct gecko_msg_le_gap_set_discovery_timing_rsp_t           rsp_le_gap_set_discovery_timing;
    struct gecko_msg_le_gap_set_discovery_type_cmd_t             cmd_le_gap_set_discovery_type;
    struct gecko_msg_le_gap_set_discovery_type_rsp_t             rsp_le_gap_set_discovery_type;
    struct gecko_msg_le_gap_start_discovery_cmd_t                cmd_le_gap_start_discovery;
    struct gecko_msg_le_gap_start_discovery_rsp_t                rsp_le_gap_start_discovery;
    struct gecko_msg_le_gap_set_data_channel_classification_cmd_t cmd_le_gap_set_data_channel_classification;
    struct gecko_msg_le_gap_set_data_channel_classification_rsp_t rsp_le_gap_set_data_channel_classification;
    struct gecko_msg_le_gap_connect_cmd_t                        cmd_le_gap_connect;
    struct gecko_msg_le_gap_connect_rsp_t                        rsp_le_gap_connect;
    struct gecko_msg_le_gap_set_advertise_tx_power_cmd_t         cmd_le_gap_set_advertise_tx_power;
    struct gecko_msg_le_gap_set_advertise_tx_power_rsp_t         rsp_le_gap_set_advertise_tx_power;
    struct gecko_msg_le_gap_set_discovery_extended_scan_response_cmd_t cmd_le_gap_set_discovery_extended_scan_response;
    struct gecko_msg_le_gap_set_discovery_extended_scan_response_rsp_t rsp_le_gap_set_discovery_extended_scan_response;
    struct gecko_msg_le_gap_start_periodic_advertising_cmd_t     cmd_le_gap_start_periodic_advertising;
    struct gecko_msg_le_gap_start_periodic_advertising_rsp_t     rsp_le_gap_start_periodic_advertising;
    struct gecko_msg_le_gap_stop_periodic_advertising_cmd_t      cmd_le_gap_stop_periodic_advertising;
    struct gecko_msg_le_gap_stop_periodic_advertising_rsp_t      rsp_le_gap_stop_periodic_advertising;
    struct gecko_msg_le_gap_enable_whitelisting_cmd_t            cmd_le_gap_enable_whitelisting;
    struct gecko_msg_le_gap_enable_whitelisting_rsp_t            rsp_le_gap_enable_whitelisting;
    struct gecko_msg_le_gap_scan_response_evt_t                  evt_le_gap_scan_response;
    struct gecko_msg_le_gap_adv_timeout_evt_t                    evt_le_gap_adv_timeout;
    struct gecko_msg_le_gap_scan_request_evt_t                   evt_le_gap_scan_request;
    struct gecko_msg_le_gap_extended_scan_response_evt_t         evt_le_gap_extended_scan_response;
    struct gecko_msg_sync_open_cmd_t                             cmd_sync_open;
    struct gecko_msg_sync_open_rsp_t                             rsp_sync_open;
    struct gecko_msg_sync_close_cmd_t                            cmd_sync_close;
    struct gecko_msg_sync_close_rsp_t                            rsp_sync_close;
    struct gecko_msg_sync_opened_evt_t                           evt_sync_opened;
    struct gecko_msg_sync_closed_evt_t                           evt_sync_closed;
    struct gecko_msg_sync_data_evt_t                             evt_sync_data;
    struct gecko_msg_le_connection_set_parameters_cmd_t          cmd_le_connection_set_parameters;
    struct gecko_msg_le_connection_set_parameters_rsp_t          rsp_le_connection_set_parameters;
    struct gecko_msg_le_connection_get_rssi_cmd_t                cmd_le_connection_get_rssi;
    struct gecko_msg_le_connection_get_rssi_rsp_t                rsp_le_connection_get_rssi;
    struct gecko_msg_le_connection_disable_slave_latency_cmd_t   cmd_le_connection_disable_slave_latency;
    struct gecko_msg_le_connection_disable_slave_latency_rsp_t   rsp_le_connection_disable_slave_latency;
    struct gecko_msg_le_connection_set_phy_cmd_t                 cmd_le_connection_set_phy;
    struct gecko_msg_le_connection_set_phy_rsp_t                 rsp_le_connection_set_phy;
    struct gecko_msg_le_connection_close_cmd_t                   cmd_le_connection_close;
    struct gecko_msg_le_connection_close_rsp_t                   rsp_le_connection_close;
    struct gecko_msg_le_connection_opened_evt_t                  evt_le_connection_opened;
    struct gecko_msg_le_connection_closed_evt_t                  evt_le_connection_closed;
    struct gecko_msg_le_connection_parameters_evt_t              evt_le_connection_parameters;
    struct gecko_msg_le_connection_rssi_evt_t                    evt_le_connection_rssi;
    struct gecko_msg_le_connection_phy_status_evt_t              evt_le_connection_phy_status;
    struct gecko_msg_gatt_set_max_mtu_cmd_t                      cmd_gatt_set_max_mtu;
    struct gecko_msg_gatt_set_max_mtu_rsp_t                      rsp_gatt_set_max_mtu;
    struct gecko_msg_gatt_discover_primary_services_cmd_t        cmd_gatt_discover_primary_services;
    struct gecko_msg_gatt_discover_primary_services_rsp_t        rsp_gatt_discover_primary_services;
    struct gecko_msg_gatt_discover_primary_services_by_uuid_cmd_t cmd_gatt_discover_primary_services_by_uuid;
    struct gecko_msg_gatt_discover_primary_services_by_uuid_rsp_t rsp_gatt_discover_primary_services_by_uuid;
    struct gecko_msg_gatt_discover_characteristics_cmd_t         cmd_gatt_discover_characteristics;
    struct gecko_msg_gatt_discover_characteristics_rsp_t         rsp_gatt_discover_characteristics;
    struct gecko_msg_gatt_discover_characteristics_by_uuid_cmd_t cmd_gatt_discover_characteristics_by_uuid;
    struct gecko_msg_gatt_discover_characteristics_by_uuid_rsp_t rsp_gatt_discover_characteristics_by_uuid;
    struct gecko_msg_gatt_set_characteristic_notification_cmd_t  cmd_gatt_set_characteristic_notification;
    struct gecko_msg_gatt_set_characteristic_notification_rsp_t  rsp_gatt_set_characteristic_notification;
    struct gecko_msg_gatt_discover_descriptors_cmd_t             cmd_gatt_discover_descriptors;
    struct gecko_msg_gatt_discover_descriptors_rsp_t             rsp_gatt_discover_descriptors;
    struct gecko_msg_gatt_read_characteristic_value_cmd_t        cmd_gatt_read_characteristic_value;
    struct gecko_msg_gatt_read_characteristic_value_rsp_t        rsp_gatt_read_characteristic_value;
    struct gecko_msg_gatt_read_characteristic_value_by_uuid_cmd_t cmd_gatt_read_characteristic_value_by_uuid;
    struct gecko_msg_gatt_read_characteristic_value_by_uuid_rsp_t rsp_gatt_read_characteristic_value_by_uuid;
    struct gecko_msg_gatt_write_characteristic_value_cmd_t       cmd_gatt_write_characteristic_value;
    struct gecko_msg_gatt_write_characteristic_value_rsp_t       rsp_gatt_write_characteristic_value;
    struct gecko_msg_gatt_write_characteristic_value_without_response_cmd_t cmd_gatt_write_characteristic_value_without_response;
    struct gecko_msg_gatt_write_characteristic_value_without_response_rsp_t rsp_gatt_write_characteristic_value_without_response;
    struct gecko_msg_gatt_prepare_characteristic_value_write_cmd_t cmd_gatt_prepare_characteristic_value_write;
    struct gecko_msg_gatt_prepare_characteristic_value_write_rsp_t rsp_gatt_prepare_characteristic_value_write;
    struct gecko_msg_gatt_execute_characteristic_value_write_cmd_t cmd_gatt_execute_characteristic_value_write;
    struct gecko_msg_gatt_execute_characteristic_value_write_rsp_t rsp_gatt_execute_characteristic_value_write;
    struct gecko_msg_gatt_send_characteristic_confirmation_cmd_t cmd_gatt_send_characteristic_confirmation;
    struct gecko_msg_gatt_send_characteristic_confirmation_rsp_t rsp_gatt_send_characteristic_confirmation;
    struct gecko_msg_gatt_read_descriptor_value_cmd_t            cmd_gatt_read_descriptor_value;
    struct gecko_msg_gatt_read_descriptor_value_rsp_t            rsp_gatt_read_descriptor_value;
    struct gecko_msg_gatt_write_descriptor_value_cmd_t           cmd_gatt_write_descriptor_value;
    struct gecko_msg_gatt_write_descriptor_value_rsp_t           rsp_gatt_write_descriptor_value;
    struct gecko_msg_gatt_find_included_services_cmd_t           cmd_gatt_find_included_services;
    struct gecko_msg_gatt_find_included_services_rsp_t           rsp_gatt_find_included_services;
    struct gecko_msg_gatt_read_multiple_characteristic_values_cmd_t cmd_gatt_read_multiple_characteristic_values;
    struct gecko_msg_gatt_read_multiple_characteristic_values_rsp_t rsp_gatt_read_multiple_characteristic_values;
    struct gecko_msg_gatt_read_characteristic_value_from_offset_cmd_t cmd_gatt_read_characteristic_value_from_offset;
    struct gecko_msg_gatt_read_characteristic_value_from_offset_rsp_t rsp_gatt_read_characteristic_value_from_offset;
    struct gecko_msg_gatt_prepare_characteristic_value_reliable_write_cmd_t cmd_gatt_prepare_characteristic_value_reliable_write;
    struct gecko_msg_gatt_prepare_characteristic_value_reliable_write_rsp_t rsp_gatt_prepare_characteristic_value_reliable_write;
    struct gecko_msg_gatt_mtu_exchanged_evt_t                    evt_gatt_mtu_exchanged;
    struct gecko_msg_gatt_service_evt_t                          evt_gatt_service;
    struct gecko_msg_gatt_characteristic_evt_t                   evt_gatt_characteristic;
    struct gecko_msg_gatt_descriptor_evt_t                       evt_gatt_descriptor;
    struct gecko_msg_gatt_characteristic_value_evt_t             evt_gatt_characteristic_value;
    struct gecko_msg_gatt_descriptor_value_evt_t                 evt_gatt_descriptor_value;
    struct gecko_msg_gatt_procedure_completed_evt_t              evt_gatt_procedure_completed;
    struct gecko_msg_gatt_server_read_attribute_value_cmd_t      cmd_gatt_server_read_attribute_value;
    struct gecko_msg_gatt_server_read_attribute_value_rsp_t      rsp_gatt_server_read_attribute_value;
    struct gecko_msg_gatt_server_read_attribute_type_cmd_t       cmd_gatt_server_read_attribute_type;
    struct gecko_msg_gatt_server_read_attribute_type_rsp_t       rsp_gatt_server_read_attribute_type;
    struct gecko_msg_gatt_server_write_attribute_value_cmd_t     cmd_gatt_server_write_attribute_value;
    struct gecko_msg_gatt_server_write_attribute_value_rsp_t     rsp_gatt_server_write_attribute_value;
    struct gecko_msg_gatt_server_send_user_read_response_cmd_t   cmd_gatt_server_send_user_read_response;
    struct gecko_msg_gatt_server_send_user_read_response_rsp_t   rsp_gatt_server_send_user_read_response;
    struct gecko_msg_gatt_server_send_user_write_response_cmd_t  cmd_gatt_server_send_user_write_response;
    struct gecko_msg_gatt_server_send_user_write_response_rsp_t  rsp_gatt_server_send_user_write_response;
    struct gecko_msg_gatt_server_send_characteristic_notification_cmd_t cmd_gatt_server_send_characteristic_notification;
    struct gecko_msg_gatt_server_send_characteristic_notification_rsp_t rsp_gatt_server_send_characteristic_notification;
    struct gecko_msg_gatt_server_find_attribute_cmd_t            cmd_gatt_server_find_attribute;
    struct gecko_msg_gatt_server_find_attribute_rsp_t            rsp_gatt_server_find_attribute;
    struct gecko_msg_gatt_server_set_capabilities_cmd_t          cmd_gatt_server_set_capabilities;
    struct gecko_msg_gatt_server_set_capabilities_rsp_t          rsp_gatt_server_set_capabilities;
    struct gecko_msg_gatt_server_attribute_value_evt_t           evt_gatt_server_attribute_value;
    struct gecko_msg_gatt_server_user_read_request_evt_t         evt_gatt_server_user_read_request;
    struct gecko_msg_gatt_server_user_write_request_evt_t        evt_gatt_server_user_write_request;
    struct gecko_msg_gatt_server_characteristic_status_evt_t     evt_gatt_server_characteristic_status;
    struct gecko_msg_gatt_server_execute_write_completed_evt_t   evt_gatt_server_execute_write_completed;
    struct gecko_msg_hardware_set_soft_timer_cmd_t               cmd_hardware_set_soft_timer;
    struct gecko_msg_hardware_set_soft_timer_rsp_t               rsp_hardware_set_soft_timer;
    struct gecko_msg_hardware_get_time_rsp_t                     rsp_hardware_get_time;
    struct gecko_msg_hardware_set_lazy_soft_timer_cmd_t          cmd_hardware_set_lazy_soft_timer;
    struct gecko_msg_hardware_set_lazy_soft_timer_rsp_t          rsp_hardware_set_lazy_soft_timer;
    struct gecko_msg_hardware_soft_timer_evt_t                   evt_hardware_soft_timer;
    struct gecko_msg_flash_ps_erase_all_rsp_t                    rsp_flash_ps_erase_all;
    struct gecko_msg_flash_ps_save_cmd_t                         cmd_flash_ps_save;
    struct gecko_msg_flash_ps_save_rsp_t                         rsp_flash_ps_save;
    struct gecko_msg_flash_ps_load_cmd_t                         cmd_flash_ps_load;
    struct gecko_msg_flash_ps_load_rsp_t                         rsp_flash_ps_load;
    struct gecko_msg_flash_ps_erase_cmd_t                        cmd_flash_ps_erase;
    struct gecko_msg_flash_ps_erase_rsp_t                        rsp_flash_ps_erase;
    struct gecko_msg_test_dtm_tx_cmd_t                           cmd_test_dtm_tx;
    struct gecko_msg_test_dtm_tx_rsp_t                           rsp_test_dtm_tx;
    struct gecko_msg_test_dtm_rx_cmd_t                           cmd_test_dtm_rx;
    struct gecko_msg_test_dtm_rx_rsp_t                           rsp_test_dtm_rx;
    struct gecko_msg_test_dtm_end_rsp_t                          rsp_test_dtm_end;
    struct gecko_msg_test_dtm_completed_evt_t                    evt_test_dtm_completed;
    struct gecko_msg_sm_set_bondable_mode_cmd_t                  cmd_sm_set_bondable_mode;
    struct gecko_msg_sm_set_bondable_mode_rsp_t                  rsp_sm_set_bondable_mode;
    struct gecko_msg_sm_configure_cmd_t                          cmd_sm_configure;
    struct gecko_msg_sm_configure_rsp_t                          rsp_sm_configure;
    struct gecko_msg_sm_store_bonding_configuration_cmd_t        cmd_sm_store_bonding_configuration;
    struct gecko_msg_sm_store_bonding_configuration_rsp_t        rsp_sm_store_bonding_configuration;
    struct gecko_msg_sm_increase_security_cmd_t                  cmd_sm_increase_security;
    struct gecko_msg_sm_increase_security_rsp_t                  rsp_sm_increase_security;
    struct gecko_msg_sm_delete_bonding_cmd_t                     cmd_sm_delete_bonding;
    struct gecko_msg_sm_delete_bonding_rsp_t                     rsp_sm_delete_bonding;
    struct gecko_msg_sm_delete_bondings_rsp_t                    rsp_sm_delete_bondings;
    struct gecko_msg_sm_enter_passkey_cmd_t                      cmd_sm_enter_passkey;
    struct gecko_msg_sm_enter_passkey_rsp_t                      rsp_sm_enter_passkey;
    struct gecko_msg_sm_passkey_confirm_cmd_t                    cmd_sm_passkey_confirm;
    struct gecko_msg_sm_passkey_confirm_rsp_t                    rsp_sm_passkey_confirm;
    struct gecko_msg_sm_set_oob_data_cmd_t                       cmd_sm_set_oob_data;
    struct gecko_msg_sm_set_oob_data_rsp_t                       rsp_sm_set_oob_data;
    struct gecko_msg_sm_list_all_bondings_rsp_t                  rsp_sm_list_all_bondings;
    struct gecko_msg_sm_bonding_confirm_cmd_t                    cmd_sm_bonding_confirm;
    struct gecko_msg_sm_bonding_confirm_rsp_t                    rsp_sm_bonding_confirm;
    struct gecko_msg_sm_set_debug_mode_rsp_t                     rsp_sm_set_debug_mode;
    struct gecko_msg_sm_set_passkey_cmd_t                        cmd_sm_set_passkey;
    struct gecko_msg_sm_set_passkey_rsp_t                        rsp_sm_set_passkey;
    struct gecko_msg_sm_use_sc_oob_cmd_t                         cmd_sm_use_sc_oob;
    struct gecko_msg_sm_use_sc_oob_rsp_t                         rsp_sm_use_sc_oob;
    struct gecko_msg_sm_set_sc_remote_oob_data_cmd_t             cmd_sm_set_sc_remote_oob_data;
    struct gecko_msg_sm_set_sc_remote_oob_data_rsp_t             rsp_sm_set_sc_remote_oob_data;
    struct gecko_msg_sm_add_to_whitelist_cmd_t                   cmd_sm_add_to_whitelist;
    struct gecko_msg_sm_add_to_whitelist_rsp_t                   rsp_sm_add_to_whitelist;
    struct gecko_msg_sm_passkey_display_evt_t                    evt_sm_passkey_display;
    struct gecko_msg_sm_passkey_request_evt_t                    evt_sm_passkey_request;
    struct gecko_msg_sm_confirm_passkey_evt_t                    evt_sm_confirm_passkey;
    struct gecko_msg_sm_bonded_evt_t                             evt_sm_bonded;
    struct gecko_msg_sm_bonding_failed_evt_t                     evt_sm_bonding_failed;
    struct gecko_msg_sm_list_bonding_entry_evt_t                 evt_sm_list_bonding_entry;
    struct gecko_msg_sm_confirm_bonding_evt_t                    evt_sm_confirm_bonding;
    struct gecko_msg_homekit_configure_cmd_t                     cmd_homekit_configure;
    struct gecko_msg_homekit_configure_rsp_t                     rsp_homekit_configure;
    struct gecko_msg_homekit_advertise_cmd_t                     cmd_homekit_advertise;
    struct gecko_msg_homekit_advertise_rsp_t                     rsp_homekit_advertise;
    struct gecko_msg_homekit_delete_pairings_rsp_t               rsp_homekit_delete_pairings;
    struct gecko_msg_homekit_check_authcp_rsp_t                  rsp_homekit_check_authcp;
    struct gecko_msg_homekit_get_pairing_id_cmd_t                cmd_homekit_get_pairing_id;
    struct gecko_msg_homekit_get_pairing_id_rsp_t                rsp_homekit_get_pairing_id;
    struct gecko_msg_homekit_send_write_response_cmd_t           cmd_homekit_send_write_response;
    struct gecko_msg_homekit_send_write_response_rsp_t           rsp_homekit_send_write_response;
    struct gecko_msg_homekit_send_read_response_cmd_t            cmd_homekit_send_read_response;
    struct gecko_msg_homekit_send_read_response_rsp_t            rsp_homekit_send_read_response;
    struct gecko_msg_homekit_gsn_action_cmd_t                    cmd_homekit_gsn_action;
    struct gecko_msg_homekit_gsn_action_rsp_t                    rsp_homekit_gsn_action;
    struct gecko_msg_homekit_event_notification_cmd_t            cmd_homekit_event_notification;
    struct gecko_msg_homekit_event_notification_rsp_t            rsp_homekit_event_notification;
    struct gecko_msg_homekit_broadcast_action_cmd_t              cmd_homekit_broadcast_action;
    struct gecko_msg_homekit_broadcast_action_rsp_t              rsp_homekit_broadcast_action;
    struct gecko_msg_homekit_setupcode_display_evt_t             evt_homekit_setupcode_display;
    struct gecko_msg_homekit_paired_evt_t                        evt_homekit_paired;
    struct gecko_msg_homekit_pair_verified_evt_t                 evt_homekit_pair_verified;
    struct gecko_msg_homekit_connection_opened_evt_t             evt_homekit_connection_opened;
    struct gecko_msg_homekit_connection_closed_evt_t             evt_homekit_connection_closed;
    struct gecko_msg_homekit_identify_evt_t                      evt_homekit_identify;
    struct gecko_msg_homekit_write_request_evt_t                 evt_homekit_write_request;
    struct gecko_msg_homekit_read_request_evt_t                  evt_homekit_read_request;
    struct gecko_msg_homekit_disconnection_required_evt_t        evt_homekit_disconnection_required;
    struct gecko_msg_homekit_pairing_removed_evt_t               evt_homekit_pairing_removed;
    struct gecko_msg_homekit_setuppayload_display_evt_t          evt_homekit_setuppayload_display;
    struct gecko_msg_coex_set_options_cmd_t                      cmd_coex_set_options;
    struct gecko_msg_coex_set_options_rsp_t                      rsp_coex_set_options;
    struct gecko_msg_coex_get_counters_cmd_t                     cmd_coex_get_counters;
    struct gecko_msg_coex_get_counters_rsp_t                     rsp_coex_get_counters;
    struct gecko_msg_l2cap_coc_send_connection_request_cmd_t     cmd_l2cap_coc_send_connection_request;
    struct gecko_msg_l2cap_coc_send_connection_request_rsp_t     rsp_l2cap_coc_send_connection_request;
    struct gecko_msg_l2cap_coc_send_connection_response_cmd_t    cmd_l2cap_coc_send_connection_response;
    struct gecko_msg_l2cap_coc_send_connection_response_rsp_t    rsp_l2cap_coc_send_connection_response;
    struct gecko_msg_l2cap_coc_send_le_flow_control_credit_cmd_t cmd_l2cap_coc_send_le_flow_control_credit;
    struct gecko_msg_l2cap_coc_send_le_flow_control_credit_rsp_t rsp_l2cap_coc_send_le_flow_control_credit;
    struct gecko_msg_l2cap_coc_send_disconnection_request_cmd_t  cmd_l2cap_coc_send_disconnection_request;
    struct gecko_msg_l2cap_coc_send_disconnection_request_rsp_t  rsp_l2cap_coc_send_disconnection_request;
    struct gecko_msg_l2cap_coc_send_data_cmd_t                   cmd_l2cap_coc_send_data;
    struct gecko_msg_l2cap_coc_send_data_rsp_t                   rsp_l2cap_coc_send_data;
    struct gecko_msg_l2cap_coc_connection_request_evt_t          evt_l2cap_coc_connection_request;
    struct gecko_msg_l2cap_coc_connection_response_evt_t         evt_l2cap_coc_connection_response;
    struct gecko_msg_l2cap_coc_le_flow_control_credit_evt_t      evt_l2cap_coc_le_flow_control_credit;
    struct gecko_msg_l2cap_coc_channel_disconnected_evt_t        evt_l2cap_coc_channel_disconnected;
    struct gecko_msg_l2cap_coc_data_evt_t                        evt_l2cap_coc_data;
    struct gecko_msg_l2cap_command_rejected_evt_t                evt_l2cap_command_rejected;
    struct gecko_msg_cte_transmitter_enable_cte_response_cmd_t   cmd_cte_transmitter_enable_cte_response;
    struct gecko_msg_cte_transmitter_enable_cte_response_rsp_t   rsp_cte_transmitter_enable_cte_response;
    struct gecko_msg_cte_transmitter_disable_cte_response_cmd_t  cmd_cte_transmitter_disable_cte_response;
    struct gecko_msg_cte_transmitter_disable_cte_response_rsp_t  rsp_cte_transmitter_disable_cte_response;
    struct gecko_msg_cte_transmitter_start_connectionless_cte_cmd_t cmd_cte_transmitter_start_connectionless_cte;
    struct gecko_msg_cte_transmitter_start_connectionless_cte_rsp_t rsp_cte_transmitter_start_connectionless_cte;
    struct gecko_msg_cte_transmitter_stop_connectionless_cte_cmd_t cmd_cte_transmitter_stop_connectionless_cte;
    struct gecko_msg_cte_transmitter_stop_connectionless_cte_rsp_t rsp_cte_transmitter_stop_connectionless_cte;
    struct gecko_msg_cte_transmitter_set_dtm_parameters_cmd_t    cmd_cte_transmitter_set_dtm_parameters;
    struct gecko_msg_cte_transmitter_set_dtm_parameters_rsp_t    rsp_cte_transmitter_set_dtm_parameters;
    struct gecko_msg_cte_transmitter_clear_dtm_parameters_rsp_t  rsp_cte_transmitter_clear_dtm_parameters;
    struct gecko_msg_cte_receiver_configure_cmd_t                cmd_cte_receiver_configure;
    struct gecko_msg_cte_receiver_configure_rsp_t                rsp_cte_receiver_configure;
    struct gecko_msg_cte_receiver_start_iq_sampling_cmd_t        cmd_cte_receiver_start_iq_sampling;
    struct gecko_msg_cte_receiver_start_iq_sampling_rsp_t        rsp_cte_receiver_start_iq_sampling;
    struct gecko_msg_cte_receiver_stop_iq_sampling_cmd_t         cmd_cte_receiver_stop_iq_sampling;
    struct gecko_msg_cte_receiver_stop_iq_sampling_rsp_t         rsp_cte_receiver_stop_iq_sampling;
    struct gecko_msg_cte_receiver_start_connectionless_iq_sampling_cmd_t cmd_cte_receiver_start_connectionless_iq_sampling;
    struct gecko_msg_cte_receiver_start_connectionless_iq_sampling_rsp_t rsp_cte_receiver_start_connectionless_iq_sampling;
    struct gecko_msg_cte_receiver_stop_connectionless_iq_sampling_cmd_t cmd_cte_receiver_stop_connectionless_iq_sampling;
    struct gecko_msg_cte_receiver_stop_connectionless_iq_sampling_rsp_t rsp_cte_receiver_stop_connectionless_iq_sampling;
    struct gecko_msg_cte_receiver_set_dtm_parameters_cmd_t       cmd_cte_receiver_set_dtm_parameters;
    struct gecko_msg_cte_receiver_set_dtm_parameters_rsp_t       rsp_cte_receiver_set_dtm_parameters;
    struct gecko_msg_cte_receiver_clear_dtm_parameters_rsp_t     rsp_cte_receiver_clear_dtm_parameters;
    struct gecko_msg_cte_receiver_iq_report_evt_t                evt_cte_receiver_iq_report;
    struct gecko_msg_user_message_to_target_cmd_t                cmd_user_message_to_target;
    struct gecko_msg_user_message_to_target_rsp_t                rsp_user_message_to_target;
    struct gecko_msg_user_message_to_host_evt_t                  evt_user_message_to_host;

    uint8 payload[BGLIB_MSG_MAX_PAYLOAD];
}data;

});


void gecko_handle_command(uint32_t,void*);
void gecko_handle_command_noresponse(uint32_t,void*);

extern struct gecko_cmd_packet*  gecko_cmd_msg;
extern struct gecko_cmd_packet*  gecko_rsp_msg;

/** 
*
* gecko_cmd_dfu_reset
*
* This command can be used to reset the system. This command does not have a response, but it triggers one of the boot events (normal reset or boot to DFU mode) after re-boot.  
*
* @param dfu   Boot mode:                     
*  - 0: Normal reset
*  - 1: Boot to UART DFU mode
*  - 2: Boot to OTA DFU mode
* 
*
* Events generated
*
* gecko_evt_system_boot - Sent after the device has booted into normal mode
* gecko_evt_dfu_boot - Sent after the device has booted into UART DFU mode    
*
**/

static inline void* gecko_cmd_dfu_reset(uint8 dfu)
{
    
    gecko_cmd_msg->data.cmd_dfu_reset.dfu=dfu;
    gecko_cmd_msg->header=((gecko_cmd_dfu_reset_id+((1)<<8)));
    
    gecko_handle_command_noresponse(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    return 0;
}

/** 
*
* gecko_cmd_dfu_flash_set_address
*
* After re-booting the local device into DFU mode, this command can be used to define the starting address on the flash to where the new firmware will be written in. 
*
* @param address   The offset in the flash where the new firmware is uploaded to. Always use the value 0x00000000.    
*
**/

static inline struct gecko_msg_dfu_flash_set_address_rsp_t* gecko_cmd_dfu_flash_set_address(uint32 address)
{
    if(ENDIAN) reverse_endian((uint8*)&address,4);
    
    gecko_cmd_msg->data.cmd_dfu_flash_set_address.address=address;
    gecko_cmd_msg->header=((gecko_cmd_dfu_flash_set_address_id+((4)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_dfu_flash_set_address;
}

/** 
*
* gecko_cmd_dfu_flash_upload
*
* This command can be used to upload the whole firmware image file into the Bluetooth device. The passed data length must be a multiple of 4 bytes. As the BGAPI command payload size is limited, multiple commands need to be issued one after the other until the whole .bin firmware image file is uploaded to the device. The next address of the flash sector in memory to write to is automatically updated by the bootloader after each individual command. 
*
* @param data   An array of data which will be written onto the flash.    
*
**/

static inline struct gecko_msg_dfu_flash_upload_rsp_t* gecko_cmd_dfu_flash_upload(uint8 data_len, const uint8* data_data)
{   
    gecko_cmd_msg->data.cmd_dfu_flash_upload.data.len=data_len;
    memcpy(gecko_cmd_msg->data.cmd_dfu_flash_upload.data.data,data_data,data_len);
    gecko_cmd_msg->header=((gecko_cmd_dfu_flash_upload_id+((1+data_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_dfu_flash_upload;
}

/** 
*
* gecko_cmd_dfu_flash_upload_finish
*
* This command can be used to tell to the device that the DFU file has been fully uploaded. To return the device back to normal mode the command "DFU Reset " must be issued next. 
*    
*
**/

static inline struct gecko_msg_dfu_flash_upload_finish_rsp_t* gecko_cmd_dfu_flash_upload_finish()
{
    
    gecko_cmd_msg->header=((gecko_cmd_dfu_flash_upload_finish_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_dfu_flash_upload_finish;
}

/** 
*
* gecko_cmd_system_hello
*
* This command does not trigger any event but the response to the command is used to verify that communication between the host and the device is working. 
*    
*
**/

static inline struct gecko_msg_system_hello_rsp_t* gecko_cmd_system_hello()
{
    
    gecko_cmd_msg->header=((gecko_cmd_system_hello_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_system_hello;
}

/** 
*
* gecko_cmd_system_reset
*
* This command can be used to reset the system. It does not have a response, but it triggers one of the boot events (normal reset or boot to DFU mode) depending on the selected boot mode. 
*
* @param dfu   Boot mode:      
*  - 0: Normal reset
*  - 1: Boot to UART DFU mode
*  - 2: Boot to OTA DFU mode
* 
*
* Events generated
*
* gecko_evt_system_boot - Sent after the device has booted into normal mode
* gecko_evt_dfu_boot - Sent after the device has booted into UART DFU mode    
*
**/

static inline void* gecko_cmd_system_reset(uint8 dfu)
{
    
    gecko_cmd_msg->data.cmd_system_reset.dfu=dfu;
    gecko_cmd_msg->header=((gecko_cmd_system_reset_id+((1)<<8)));
    
    gecko_handle_command_noresponse(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    return 0;
}

/** 
*
* gecko_cmd_system_get_bt_address
*
* This command can be used to read the Bluetooth public address used by the device. 
*    
*
**/

static inline struct gecko_msg_system_get_bt_address_rsp_t* gecko_cmd_system_get_bt_address()
{
    
    gecko_cmd_msg->header=((gecko_cmd_system_get_bt_address_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_system_get_bt_address_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_system_get_bt_address;
}

/** 
*
* gecko_cmd_system_set_bt_address
*
* Deprecated. Replacement is "system_set_identity_address" command.                 
* This command can be used to set the Bluetooth public address used by
* the device. A valid address set with this command overrides the
* default Bluetooth public address programmed at production, and it will
* be effective in the next system reboot. The stack treats
* 00:00:00:00:00:00 and ff:ff:ff:ff:ff:ff as invalid addresses. Thus
* passing one of them into this command will cause the stack to use the
* default address in the next system reboot.
*  
*
* @param address   Bluetooth public address in little endian format    
*
**/
BGLIB_DEPRECATED_API 
static inline struct gecko_msg_system_set_bt_address_rsp_t* gecko_cmd_system_set_bt_address(bd_addr address)
{
    
    memcpy(&gecko_cmd_msg->data.cmd_system_set_bt_address.address,&address,sizeof(bd_addr));
    gecko_cmd_msg->header=((gecko_cmd_system_set_bt_address_id+((6)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_system_set_bt_address;
}

/** 
*
* gecko_cmd_system_set_tx_power
*
* This command can be used to set the global maximum TX power for Bluetooth.                 The returned value in the response is the selected maximum output power level after applying RF path compensation. If the GATT server contains a Tx Power service, the Tx Power Level attribute of the service will be updated accordingly.                 
* The selected power level may be less than the specified value if the
* device does not meet the power requirements. For Bluetooth connections
* the maximum TX power will be limited to 10 dBm if Adaptive Frequency
* Hopping (AFH) is not enabled.
* By default, the global maximum TX power value is 8 dBm.
* NOTE: This command should not be used while advertising, scanning or during connection.
*  
*
* @param power   TX power in 0.1dBm steps, for example the value of 10 is 1dBm and 55 is 5.5dBm    
*
**/

static inline struct gecko_msg_system_set_tx_power_rsp_t* gecko_cmd_system_set_tx_power(int16 power)
{
    if(ENDIAN) reverse_endian((uint8*)&power,2);

    gecko_cmd_msg->data.cmd_system_set_tx_power.power=power;
    gecko_cmd_msg->header=((gecko_cmd_system_set_tx_power_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_system_set_tx_power_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_system_set_tx_power;
}

/** 
*
* gecko_cmd_system_get_random_data
*
* This command can be used to get random data up to 16 bytes.              
*
* @param length   Length of random data. Maximum length is 16 bytes.    
*
**/

static inline struct gecko_msg_system_get_random_data_rsp_t* gecko_cmd_system_get_random_data(uint8 length)
{
    
    gecko_cmd_msg->data.cmd_system_get_random_data.length=length;
    gecko_cmd_msg->header=((gecko_cmd_system_get_random_data_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_system_get_random_data;
}

/** 
*
* gecko_cmd_system_halt
*
* This command forces radio to idle state and allows device to sleep. Advertising, scanning, connections and software timers are halted by this commands. Halted operations are resumed by calling this command with parameter 0. Connections stay alive if system is resumed before connection supervision timeout.                 
* This command should only be used for a short time period (a few
* seconds at maximum).                 It halts Bluetooth activity, but
* all the tasks and operations are still existing inside
* stack with their own concepts of time. Halting the system for a long
* time period may                 have negative consequences on stack's
* internal states.
* NOTE:Software timer is also halted. Hardware interrupts are the only way to wake up from                 energy mode 2 when system is halted.
*  
*
* @param halt   Values:
*  - 1: halt
*  - 0: resume
*     
*
**/

static inline struct gecko_msg_system_halt_rsp_t* gecko_cmd_system_halt(uint8 halt)
{
    
    gecko_cmd_msg->data.cmd_system_halt.halt=halt;
    gecko_cmd_msg->header=((gecko_cmd_system_halt_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_system_halt;
}

/** 
*
* gecko_cmd_system_set_device_name
*
* This command can be used to set the device name. Currently it is possible to set the name which will be used during the OTA update. The name will be stored in persistent storage.             If the OTA device name is also set in gecko configuration, the name stored in persistent storage is overwritten with the name in gecko configuration during device boot. 
*
* @param type   Device name to set. Values:
*  - 0: OTA device name
* 
* @param name   Device name    
*
**/

static inline struct gecko_msg_system_set_device_name_rsp_t* gecko_cmd_system_set_device_name(uint8 type,uint8 name_len, const uint8* name_data)
{

    gecko_cmd_msg->data.cmd_system_set_device_name.type=type;
    gecko_cmd_msg->data.cmd_system_set_device_name.name.len=name_len;
    memcpy(gecko_cmd_msg->data.cmd_system_set_device_name.name.data,name_data,name_len);
    gecko_cmd_msg->header=((gecko_cmd_system_set_device_name_id+((2+name_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_system_set_device_name;
}

/** 
*
* gecko_cmd_system_linklayer_configure
*
* Send configuration data to linklayer. This command is used to fine tune low level Bluetooth operation. 
*
* @param key   Key to configure:      
*  - 1:HALT, same as system_halt command, value-0 Stop Radio 1- Start Radio
*  - 2:PRIORITY_RANGE, Sets RAIL priority_mapping offset field of linklayer Priority configuration structure to the first byte of value field.
*  - 3:SCAN_CHANNELS, Sets channels to scan on. First byte of value is channel map. 0x1 = Channel 37, 0x2 = Channel 38, 0x4 = Channel 39
*  - 4:SET_FLAGS, Set Link Layer configuration flags. value is little endian 32bit integer.      Flag Values:       
*  - 0x00000001 - Disable Feature Exchange when slave
*  - 0x00000002 - Disable Feature Exchange when master
*  - 5:CLR_FLAGS, value is flags to clear. Flags are same as in SET_FLAGS command.
*  - 7:SET_AFH_INTERVAL, Set afh_scan_interval field of Link Layer priority configuration structure.
*  - 0:
* 
* @param data   Configuration data. Length and contents of data field depend on the key value used.    
*
**/

static inline struct gecko_msg_system_linklayer_configure_rsp_t* gecko_cmd_system_linklayer_configure(uint8 key,uint8 data_len, const uint8* data_data)
{

    gecko_cmd_msg->data.cmd_system_linklayer_configure.key=key;
    gecko_cmd_msg->data.cmd_system_linklayer_configure.data.len=data_len;
    memcpy(gecko_cmd_msg->data.cmd_system_linklayer_configure.data.data,data_data,data_len);
    gecko_cmd_msg->header=((gecko_cmd_system_linklayer_configure_id+((2+data_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_system_linklayer_configure;
}

/** 
*
* gecko_cmd_system_get_counters
*
* Get packet and error counters 
*
* @param reset   Reset counters if parameter value is nonzero    
*
**/

static inline struct gecko_msg_system_get_counters_rsp_t* gecko_cmd_system_get_counters(uint8 reset)
{
    
    gecko_cmd_msg->data.cmd_system_get_counters.reset=reset;
    gecko_cmd_msg->header=((gecko_cmd_system_get_counters_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_system_get_counters;
}

/** 
*
* gecko_cmd_system_set_identity_address
*
* This command can be used to set the device's Bluetooth identity address.                 The address can be a public device address or static random address.                 A valid address set with this command overrides the default Bluetooth public                 address that was programmed at production, and it will be effective in the next system reboot.                 The stack treats 00:00:00:00:00:00 and ff:ff:ff:ff:ff:ff as invalid addresses.                 Thus passing one of them into this command will cause the stack to use the default address in next system reboot.              
*
* @param address   Bluetooth identity address in little endian format
* @param type   Address type                     
*  - 0: Public device address
*  - 1: Static random address
*     
*
**/

static inline struct gecko_msg_system_set_identity_address_rsp_t* gecko_cmd_system_set_identity_address(bd_addr address,uint8 type)
{
    
    memcpy(&gecko_cmd_msg->data.cmd_system_set_identity_address.address,&address,sizeof(bd_addr));
    gecko_cmd_msg->data.cmd_system_set_identity_address.type=type;
    gecko_cmd_msg->header=((gecko_cmd_system_set_identity_address_id+((7)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_system_set_identity_address;
}

/** 
*
* gecko_cmd_le_gap_open
*
* Deprecated. Replacement is "le_gap_connect" command which allows to open a connection with a specified PHY.
* This command can be used to connect an advertising device with
* initiating PHY being the LE 1M PHY.
*  
*
* @param address   Address of the device to connect to
* @param address_type   Address type of the device to connect to
*
* Events generated
*
* gecko_evt_le_connection_opened - This event is triggered after the connection has been opened, and indicates whether the devices are already bonded and what is the role of the Bluetooth device (Slave or Master).
* gecko_evt_le_connection_parameters - This event indicates the connection parameters and security mode of the connection.    
*
**/
BGLIB_DEPRECATED_API 
static inline struct gecko_msg_le_gap_open_rsp_t* gecko_cmd_le_gap_open(bd_addr address,uint8 address_type)
{
    
    memcpy(&gecko_cmd_msg->data.cmd_le_gap_open.address,&address,sizeof(bd_addr));
    gecko_cmd_msg->data.cmd_le_gap_open.address_type=address_type;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_open_id+((7)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_open;
}

/** 
*
* gecko_cmd_le_gap_set_mode
*
* Deprecated. Use "le_gap_start_advertising" command for enabling the advertising, and "le_gap_stop_advertising" command for disabling the advertising.
* This command is only effective on the first advertising set (handle
* value 0). Other advertising sets are not affected.
*  
*
* @param discover   Discoverable mode
* @param connect   Connectable mode
*
* Events generated
*
* gecko_evt_le_gap_adv_timeout - Triggered when the number of advertising events has been done and advertising is stopped.
* gecko_evt_le_connection_opened - Triggered when a remote device opened a connection to this advertising device.    
*
**/
BGLIB_DEPRECATED_API 
static inline struct gecko_msg_le_gap_set_mode_rsp_t* gecko_cmd_le_gap_set_mode(uint8 discover,uint8 connect)
{
    
    gecko_cmd_msg->data.cmd_le_gap_set_mode.discover=discover;
    gecko_cmd_msg->data.cmd_le_gap_set_mode.connect=connect;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_mode_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_mode;
}

/** 
*
* gecko_cmd_le_gap_discover
*
* Deprecated. Replacement is "le_gap_start_discovery" command which allows to scan on LE 1M PHY or LE Coded PHY.
* This command can be used to start the GAP discovery procedure to scan
* for advertising devices on LE 1M PHY. To cancel an ongoing
* discovery process use the "le_gap_end_procedure" command.
*  
*
* @param mode   Bluetooth discovery Mode. For values see link
*
* Events generated
*
* gecko_evt_le_gap_scan_response - Every time an advertising packet is received, this event is triggered. The packets are not filtered in any way, so multiple events will be                     received for every advertising device in range.    
*
**/
BGLIB_DEPRECATED_API 
static inline struct gecko_msg_le_gap_discover_rsp_t* gecko_cmd_le_gap_discover(uint8 mode)
{
    
    gecko_cmd_msg->data.cmd_le_gap_discover.mode=mode;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_discover_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_discover;
}

/** 
*
* gecko_cmd_le_gap_end_procedure
*
* This command can be used to end a current GAP procedure. 
*    
*
**/

static inline struct gecko_msg_le_gap_end_procedure_rsp_t* gecko_cmd_le_gap_end_procedure()
{
    
    gecko_cmd_msg->header=((gecko_cmd_le_gap_end_procedure_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_le_gap_end_procedure_id))
    {
        return NULL;
    }    

    return &gecko_rsp_msg->data.rsp_le_gap_end_procedure;
}

/** 
*
* gecko_cmd_le_gap_set_adv_parameters
*
* Deprecated. Replacements are "le_gap_set_advertise_timing" command for setting the advertising intervals, and "le_gap_set_advertise_channel_map" command for setting the channel map.
* This command is only effective on the first advertising set (handle
* value 0). Other advertising sets are not affected.
*  
*
* @param interval_min   Minimum advertising interval. Value in units of 0.625 ms
*  - Range: 0x20 to 0xFFFF
*  - Time range: 20 ms to 40.96 s
* Default value: 100 ms
* @param interval_max   Maximum advertising interval. Value in units of 0.625 ms
*  - Range: 0x20 to 0xFFFF
*  - Time range: 20 ms to 40.96 s
*  - Note: interval_max should be bigger than interval_min
* Default value: 200 ms
* @param channel_map   Advertising channel map which determines which of the three channels will be used for advertising. This value is given as a bitmask. Values:
*  - 1: Advertise on CH37
*  - 2: Advertise on CH38
*  - 3: Advertise on CH37 and CH38
*  - 4: Advertise on CH39
*  - 5: Advertise on CH37 and CH39
*  - 6: Advertise on CH38 and CH39
*  - 7: Advertise on all channels
* Recommended value: 7
* Default value: 7    
*
**/
BGLIB_DEPRECATED_API 
static inline struct gecko_msg_le_gap_set_adv_parameters_rsp_t* gecko_cmd_le_gap_set_adv_parameters(uint16 interval_min,uint16 interval_max,uint8 channel_map)
{
    if(ENDIAN) reverse_endian((uint8*)&interval_min,2);
    if(ENDIAN) reverse_endian((uint8*)&interval_max,2);
    
    gecko_cmd_msg->data.cmd_le_gap_set_adv_parameters.interval_min=interval_min;
    gecko_cmd_msg->data.cmd_le_gap_set_adv_parameters.interval_max=interval_max;
    gecko_cmd_msg->data.cmd_le_gap_set_adv_parameters.channel_map=channel_map;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_adv_parameters_id+((5)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_adv_parameters;
}

/** 
*
* gecko_cmd_le_gap_set_conn_parameters
*
* This command can be used to set the default Bluetooth connection parameters. The configured values are valid for all subsequent connections that will              be established. For changing the parameters of an already established connection use the command "le_connection_set_parameters". 
*
* @param min_interval   Minimum value for the connection event interval. This must be set be less than or equal to max_interval.
*  - Time = Value x 1.25 ms
*  - Range: 0x0006 to 0x0c80
*  - Time Range: 7.5 ms to 4 s
* Default value: 20 ms                 
* @param max_interval   Maximum value for the connection event interval. This must be set greater than or equal to min_interval.
*  - Time = Value x 1.25 ms
*  - Range: 0x0006 to 0x0c80
*  - Time Range: 7.5 ms to 4 s
* Default value: 50 ms                 
* @param latency   Slave latency. This parameter defines how many connection intervals the slave can skip if it has no data to send
*  - Range: 0x0000 to 0x01f4
* Default value: 0                 
* @param timeout   Supervision timeout. The supervision timeout defines for how long the connection is maintained despite the devices being unable to communicate at the currently configured  connection intervals.
*  - Range: 0x000a to 0x0c80
*  - Time = Value x 10 ms
*  - Time Range: 100 ms to 32 s
*  - The value in milliseconds must be larger than (1 + latency) * max_interval * 2, where max_interval is given in milliseconds
* It is recommended that the supervision timeout is set at a value which allows communication attempts over at least a few connection intervals.
* Default value: 1000 ms
*     
*
**/

static inline struct gecko_msg_le_gap_set_conn_parameters_rsp_t* gecko_cmd_le_gap_set_conn_parameters(uint16 min_interval,uint16 max_interval,uint16 latency,uint16 timeout)
{
    if(ENDIAN) reverse_endian((uint8*)&min_interval,2);
    if(ENDIAN) reverse_endian((uint8*)&max_interval,2);
    if(ENDIAN) reverse_endian((uint8*)&latency,2);
    if(ENDIAN) reverse_endian((uint8*)&timeout,2);
    
    gecko_cmd_msg->data.cmd_le_gap_set_conn_parameters.min_interval=min_interval;
    gecko_cmd_msg->data.cmd_le_gap_set_conn_parameters.max_interval=max_interval;
    gecko_cmd_msg->data.cmd_le_gap_set_conn_parameters.latency=latency;
    gecko_cmd_msg->data.cmd_le_gap_set_conn_parameters.timeout=timeout;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_conn_parameters_id+((8)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_conn_parameters;
}

/** 
*
* gecko_cmd_le_gap_set_scan_parameters
*
* Deprecated. Replacements are "le_gap_set_discovery_timing" command for setting timing parameters, and "le_gap_set_discovery_type" command for the scan type.
* The parameters set by this command is only effective on the LE 1M PHY.
* For LE Coded PHY, above replacement command must be used.
*  
*
* @param scan_interval   Scanner interval. This is defined as the time interval from when the device started its last scan until it begins the subsequent scan, that is how often to scan
*  - Time = Value x 0.625 ms
*  - Range: 0x0004 to 0x4000
*  - Time Range: 2.5 ms to 10.24 s
* Default value: 10 ms 
* There is a variable delay when switching channels at the end of each
* scanning interval which is included in the scanning interval time
* itself. During this switch time no advertising packets will be
* received by the device. The switch time variation is dependent on use
* case, for example in case of scanning while keeping active connections
* the channel switch time might be longer than when only scanning
* without any active connections. Increasing the scanning interval will
* reduce the amount of time in which the device cannot receive
* advertising packets as it will switch channels less often.
* After every scan interval the scanner will change the frequency it
* operates at. It will cycle through all the three advertising channels
* in a round robin fashion. According to the specification all three
* channels must be used by a scanner.
* 
* @param scan_window   Scan window. The duration of the scan. scan_window shall be less than or equal to scan_interval
*  - Time = Value x 0.625 ms
*  - Range: 0x0004 to 0x4000
*  - Time Range: 2.5 ms to 10.24 s
* Default value: 10 ms Note that packet reception is aborted if it has been started before scan window ends.                 
* @param active   Scan type indicated by a flag. Values:
*  - 0: Passive scanning
*  - 1: Active scanning
*  - In passive scanning mode the device only listens to advertising packets and will not transmit any packet
*  - In active scanning mode the device will send out a scan request packet upon receiving advertising packet from a remote device and then it will listen to the scan response packet from remote device
* Default value: 0                     
*
**/
BGLIB_DEPRECATED_API 
static inline struct gecko_msg_le_gap_set_scan_parameters_rsp_t* gecko_cmd_le_gap_set_scan_parameters(uint16 scan_interval,uint16 scan_window,uint8 active)
{
    if(ENDIAN) reverse_endian((uint8*)&scan_interval,2);
    if(ENDIAN) reverse_endian((uint8*)&scan_window,2);
    
    gecko_cmd_msg->data.cmd_le_gap_set_scan_parameters.scan_interval=scan_interval;
    gecko_cmd_msg->data.cmd_le_gap_set_scan_parameters.scan_window=scan_window;
    gecko_cmd_msg->data.cmd_le_gap_set_scan_parameters.active=active;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_scan_parameters_id+((5)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_scan_parameters;
}

/** 
*
* gecko_cmd_le_gap_set_adv_data
*
* Deprecated. Use "le_gap_bt5_set_adv_data" command to set the advertising data and scan response data.
* This command is only effective on the first advertising set (handle
* value 0). Other advertising sets are not affected.
*  
*
* @param scan_rsp   This value selects if the data is intended for advertising packets, scan response packets or advertising packet in OTA. Values: 
*  - 0: Advertising packets
*  - 1: Scan response packets
*  - 2: OTA advertising packets
*  - 4: OTA scan response packets
* 
* @param adv_data   Data to be set. Maximum data length: 
*  - 31 bytes for legacy advertising;
*  - 191 bytes for extended advertising
*     
*
**/
BGLIB_DEPRECATED_API 
static inline struct gecko_msg_le_gap_set_adv_data_rsp_t* gecko_cmd_le_gap_set_adv_data(uint8 scan_rsp,uint8 adv_data_len, const uint8* adv_data_data)
{

    gecko_cmd_msg->data.cmd_le_gap_set_adv_data.scan_rsp=scan_rsp;
    gecko_cmd_msg->data.cmd_le_gap_set_adv_data.adv_data.len=adv_data_len;
    memcpy(gecko_cmd_msg->data.cmd_le_gap_set_adv_data.adv_data.data,adv_data_data,adv_data_len);
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_adv_data_id+((2+adv_data_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_adv_data;
}

/** 
*
* gecko_cmd_le_gap_set_adv_timeout
*
* Deprecated. New command "le_gap_set_advertise_timing" should be used for this functionality.
* This command is only effective on the first advertising set (handle
* value 0). Other advertising sets are not affected.
*  
*
* @param maxevents   If non-zero, indicates the maximum number of advertising events to send before stopping advertiser. Value 0 indicates no maximum number limit.    
*
**/
BGLIB_DEPRECATED_API 
static inline struct gecko_msg_le_gap_set_adv_timeout_rsp_t* gecko_cmd_le_gap_set_adv_timeout(uint8 maxevents)
{
    
    gecko_cmd_msg->data.cmd_le_gap_set_adv_timeout.maxevents=maxevents;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_adv_timeout_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_adv_timeout;
}

/** 
*
* gecko_cmd_le_gap_bt5_set_mode
*
* Deprecated. Replacements are "le_gap_start_advertising" command to start the advertising, and "le_gap_stop_advertising" command to stop the advertising.             "le_gap_set_advertise_timing" command can be used for setting the maxevents and command "le_gap_set_advertise_configuration" can be used to for setting address types.
*  
*
* @param handle   Advertising set handle, number of sets available is defined in stack configuration
* @param discover   Discoverable mode
* @param connect   Connectable mode
* @param maxevents   If non-zero, indicates the maximum number of advertising events to send before stopping advertiser. Value 0 indicates no maximum number limit.
* @param address_type   Address type to use for packets
*
* Events generated
*
* gecko_evt_le_gap_adv_timeout - Triggered when the number of advertising events set by this command has been done and advertising is stopped on the given advertising set.
* gecko_evt_le_connection_opened - Triggered when a remote device opened a connection to the advertiser on the specified advertising set.    
*
**/
BGLIB_DEPRECATED_API 
static inline struct gecko_msg_le_gap_bt5_set_mode_rsp_t* gecko_cmd_le_gap_bt5_set_mode(uint8 handle,uint8 discover,uint8 connect,uint16 maxevents,uint8 address_type)
{
    if(ENDIAN) reverse_endian((uint8*)&maxevents,2);
    
    gecko_cmd_msg->data.cmd_le_gap_bt5_set_mode.handle=handle;
    gecko_cmd_msg->data.cmd_le_gap_bt5_set_mode.discover=discover;
    gecko_cmd_msg->data.cmd_le_gap_bt5_set_mode.connect=connect;
    gecko_cmd_msg->data.cmd_le_gap_bt5_set_mode.maxevents=maxevents;
    gecko_cmd_msg->data.cmd_le_gap_bt5_set_mode.address_type=address_type;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_bt5_set_mode_id+((6)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_bt5_set_mode;
}

/** 
*
* gecko_cmd_le_gap_bt5_set_adv_parameters
*
* Deprecated. Replacements are "le_gap_set_advertise_timing" command for setting the advertising intervals, "le_gap_set_advertise_channel_map" command for setting the channel map, and "le_gap_set_advertise_report_scan_request" command for enabling and disabling scan request notifications.
*  
*
* @param handle   Advertising set handle, number of sets available is defined in stack configuration
* @param interval_min   Minimum advertising interval. Value in units of 0.625 ms
*  - Range: 0x20 to 0xFFFF
*  - Time range: 20 ms to 40.96 s
* Default value: 100 ms
* @param interval_max   Maximum advertising interval. Value in units of 0.625 ms
*  - Range: 0x20 to 0xFFFF
*  - Time range: 20 ms to 40.96 s
*  - Note: interval_max should be bigger than interval_min
* Default value: 200 ms
* @param channel_map   Advertising channel map which determines which of the three channels will be used for advertising. This value is given as a bitmask. Values:
*  - 1: Advertise on CH37
*  - 2: Advertise on CH38
*  - 3: Advertise on CH37 and CH38
*  - 4: Advertise on CH39
*  - 5: Advertise on CH37 and CH39
*  - 6: Advertise on CH38 and CH39
*  - 7: Advertise on all channels
* Recommended value: 7
* Default value: 7
* @param report_scan   If non-zero, enables scan request notification, and scan requests will be reported as events.
* Default value: 0
* 
*
* Events generated
*
* gecko_evt_le_gap_scan_request - Triggered when a scan request has been received during the advertising if scan request notification has been enabled by this command.    
*
**/
BGLIB_DEPRECATED_API 
static inline struct gecko_msg_le_gap_bt5_set_adv_parameters_rsp_t* gecko_cmd_le_gap_bt5_set_adv_parameters(uint8 handle,uint16 interval_min,uint16 interval_max,uint8 channel_map,uint8 report_scan)
{
    if(ENDIAN) reverse_endian((uint8*)&interval_min,2);
    if(ENDIAN) reverse_endian((uint8*)&interval_max,2);
    
    gecko_cmd_msg->data.cmd_le_gap_bt5_set_adv_parameters.handle=handle;
    gecko_cmd_msg->data.cmd_le_gap_bt5_set_adv_parameters.interval_min=interval_min;
    gecko_cmd_msg->data.cmd_le_gap_bt5_set_adv_parameters.interval_max=interval_max;
    gecko_cmd_msg->data.cmd_le_gap_bt5_set_adv_parameters.channel_map=channel_map;
    gecko_cmd_msg->data.cmd_le_gap_bt5_set_adv_parameters.report_scan=report_scan;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_bt5_set_adv_parameters_id+((7)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_bt5_set_adv_parameters;
}

/** 
*
* gecko_cmd_le_gap_bt5_set_adv_data
*
* This command can be used to set user defined data in advertising packets, scan response packets             or periodic advertising packets.             
* If advertising mode is currently enabled the new advertising data will
* be used immediately.             Advertising mode can be enabled using
* command             "le_gap_start_advertising".             Periodic
* advertising mode can be enabled using command
* "le_gap_start_periodic_advertising".
* The maximum data length is 31 bytes for legacy advertising and 191
* bytes for extended advertising.
* The invalid parameter error will be returned in following situations:
*  - The data length is more than 31 bytes but the advertiser can only advertise using legacy advertising PDUs;
*  - The data length is more than 191 bytes when the advertiser can advertise using extended advertising PDUs;
*  - Set the data of advertising data packet when the advertiser is advertising in scannable mode using extended advertising PDUs;
*  - Set the data of scan response data packet when the advertiser is advertising in connectable mode using extended advertising PDUs.
* Note that the user defined data may be overwritten by the system when
* the advertising is later enabled in other discoverable mode than
* user_data.
*  
*
* @param handle   Advertising set handle, number of sets available is defined in stack configuration
* @param scan_rsp   This value selects if the data is intended for advertising packets, scan response packets, periodic advertising packets or advertising packet in OTA. Values:                 
*  - 0: Advertising packets
*  - 1: Scan response packets
*  - 2: OTA advertising packets
*  - 4: OTA scan response packets
*  - 8: Periodic advertising packets
* 
* @param adv_data   Data to be set. Maximum data length: 
*  - 31 bytes for legacy advertising;
*  - 191 bytes for extended advertising
*     
*
**/

static inline struct gecko_msg_le_gap_bt5_set_adv_data_rsp_t* gecko_cmd_le_gap_bt5_set_adv_data(uint8 handle,uint8 scan_rsp,uint8 adv_data_len, const uint8* adv_data_data)
{
    if ((uint16_t)adv_data_len > BGLIB_MSG_MAX_PAYLOAD - 3)
    {
        gecko_rsp_msg->data.rsp_le_gap_bt5_set_adv_data.result = bg_err_command_too_long;
        return &gecko_rsp_msg->data.rsp_le_gap_bt5_set_adv_data;
    }

    gecko_cmd_msg->data.cmd_le_gap_bt5_set_adv_data.handle=handle;
    gecko_cmd_msg->data.cmd_le_gap_bt5_set_adv_data.scan_rsp=scan_rsp;
    gecko_cmd_msg->data.cmd_le_gap_bt5_set_adv_data.adv_data.len=adv_data_len;
    memcpy(gecko_cmd_msg->data.cmd_le_gap_bt5_set_adv_data.adv_data.data,adv_data_data,adv_data_len);
    gecko_cmd_msg->header=((gecko_cmd_le_gap_bt5_set_adv_data_id+((3+adv_data_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_le_gap_bt5_set_adv_data_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_le_gap_bt5_set_adv_data;
}

/** 
*
* gecko_cmd_le_gap_set_privacy_mode
*
* This command can be used to enable or disable privacy feature on all GAP roles. The new privacy mode will take effect for advertising on the next advertising enabling, for scanning on the next scan enabling, and for initiating on the next open connection command. When privacy is enabled and the device is advertising or scanning, the stack will maintain a periodic timer with the specified time interval as timeout value. At each timeout the stack will generate a new private resolvable address and use it in advertising data packets and scanning requests.             
* By default, privacy feature is disabled.
*  
*
* @param privacy   Values: 
*  - 0: Disable privacy
*  - 1: Enable privacy
* 
* @param interval   The minimum time interval between private address change. This parameter is ignored if this command is issued for disabling privacy mode. Values: 
*  - 0: Use default interval, 15 minutes
*  - others: The time interval in minutes
*     
*
**/

static inline struct gecko_msg_le_gap_set_privacy_mode_rsp_t* gecko_cmd_le_gap_set_privacy_mode(uint8 privacy,uint8 interval)
{
    
    gecko_cmd_msg->data.cmd_le_gap_set_privacy_mode.privacy=privacy;
    gecko_cmd_msg->data.cmd_le_gap_set_privacy_mode.interval=interval;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_privacy_mode_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_privacy_mode;
}

/** 
*
* gecko_cmd_le_gap_set_advertise_timing
*
* This command can be used to set the advertising timing parameters of the given advertising set. This setting will take effect on the next advertising enabling. 
*
* @param handle   Advertising set handle
* @param interval_min   Minimum advertising interval. Value in units of 0.625 ms
*  - Range: 0x20 to 0xFFFF
*  - Time range: 20 ms to 40.96 s
* Default value: 100 ms
* @param interval_max   Maximum advertising interval. Value in units of 0.625 ms
*  - Range: 0x20 to 0xFFFF
*  - Time range: 20 ms to 40.96 s
*  - Note: interval_max should be bigger than interval_min
* Default value: 200 ms
* @param duration   The advertising duration for this advertising set. Value 0 indicates no advertising duration limit and the advertising continues until it is disabled. A non-zero value sets the duration in units of 10 ms. The duration begins at the start of the first advertising event of this advertising set.
*  - Range: 0x0001 to 0xFFFF
*  - Time range: 10 ms to 655.35 s
* Default value: 0
* @param maxevents   If non-zero, indicates the maximum number of advertising events to send before stopping advertiser. Value 0 indicates no maximum number limit. 
* Default value: 0
*     
*
**/

static inline struct gecko_msg_le_gap_set_advertise_timing_rsp_t* gecko_cmd_le_gap_set_advertise_timing(uint8 handle,uint32 interval_min,uint32 interval_max,uint16 duration,uint8 maxevents)
{
    if(ENDIAN) reverse_endian((uint8*)&interval_min,4);
    if(ENDIAN) reverse_endian((uint8*)&interval_max,4);
    if(ENDIAN) reverse_endian((uint8*)&duration,2);
    
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_timing.handle=handle;
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_timing.interval_min=interval_min;
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_timing.interval_max=interval_max;
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_timing.duration=duration;
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_timing.maxevents=maxevents;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_advertise_timing_id+((12)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_le_gap_set_advertise_timing_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_le_gap_set_advertise_timing;
}

/** 
*
* gecko_cmd_le_gap_set_advertise_channel_map
*
* This command can be used to set the primary advertising channel map of the given advertising set. This setting will take effect on the next advertising enabling. 
*
* @param handle   Advertising set handle
* @param channel_map   Advertisement channel map which determines which of the three channels will be used for advertising. This value is given as a bitmask. Values:
*  - 1: Advertise on CH37
*  - 2: Advertise on CH38
*  - 3: Advertise on CH37 and CH38
*  - 4: Advertise on CH39
*  - 5: Advertise on CH37 and CH39
*  - 6: Advertise on CH38 and CH39
*  - 7: Advertise on all channels
* Recommended value: 7
* Default value: 7    
*
**/

static inline struct gecko_msg_le_gap_set_advertise_channel_map_rsp_t* gecko_cmd_le_gap_set_advertise_channel_map(uint8 handle,uint8 channel_map)
{
    
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_channel_map.handle=handle;
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_channel_map.channel_map=channel_map;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_advertise_channel_map_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_advertise_channel_map;
}

/** 
*
* gecko_cmd_le_gap_set_advertise_report_scan_request
*
* This command can be used to enable or disable the scan request notification of the given advertising set. This setting will take effect on the next advertising enabling. 
*
* @param handle   Advertising set handle
* @param report_scan_req   If non-zero, enables scan request notification, and scan requests will be reported as events.
* Default value: 0
* 
*
* Events generated
*
* gecko_evt_le_gap_scan_request - Triggered when a scan request has been received during the advertising if scan request notification has been enabled by this command.    
*
**/

static inline struct gecko_msg_le_gap_set_advertise_report_scan_request_rsp_t* gecko_cmd_le_gap_set_advertise_report_scan_request(uint8 handle,uint8 report_scan_req)
{
    
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_report_scan_request.handle=handle;
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_report_scan_request.report_scan_req=report_scan_req;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_advertise_report_scan_request_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_advertise_report_scan_request;
}

/** 
*
* gecko_cmd_le_gap_set_advertise_phy
*
* This command can be used to set the advertising PHYs of the given advertising set. This setting will take effect on the next advertising enabling. "Invalid Parameter" error will be returned if a PHY value is invalid or the device does not support a given PHY. 
*
* @param handle   Advertising set handle
* @param primary_phy   The PHY on which the advertising packets are transmitted on the primary advertising channel. If legacy advertising PDUs are being used, the PHY must be LE 1M.
* Values:
*  - 1: Advertising PHY is LE 1M
*  - 4: Advertising PHY is LE Coded
* Default: 1
* 
* @param secondary_phy   The PHY on which the advertising packets are transmitted on the secondary advertising channel.
* Values:
*  - 1: Advertising PHY is LE 1M
*  - 2: Advertising PHY is LE 2M
*  - 4: Advertising PHY is LE Coded
* Default: 1
*     
*
**/

static inline struct gecko_msg_le_gap_set_advertise_phy_rsp_t* gecko_cmd_le_gap_set_advertise_phy(uint8 handle,uint8 primary_phy,uint8 secondary_phy)
{
    
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_phy.handle=handle;
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_phy.primary_phy=primary_phy;
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_phy.secondary_phy=secondary_phy;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_advertise_phy_id+((3)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);

	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_le_gap_set_advertise_phy_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_le_gap_set_advertise_phy;
}

/** 
*
* gecko_cmd_le_gap_set_advertise_configuration
*
* This command can be used to configure the type of advertising event and other advertising properties of the given advertising set. The command "le_gap_clear_advertise_configuration" can be used to clear the configurations set by this command. This setting will take effect on the next advertising enabling. 
*
* @param handle   Advertising set handle
* @param configurations   Advertising configuration flags to enable. This value can be a bitmask of multiple flags. Flags:                 
*  - 1 (Bit 0): Use legacy advertising PDUs. 
*  - 2 (Bit 1): Omit advertiser's address from all PDUs (anonymous advertising). This flag is effective only in extended advertising.
*  - 4 (Bit 2): Use le_gap_non_resolvable address type. Advertising must be in non-connectable mode if this configuration is enabled.
*  - 8 (Bit 3): Include TX power in advertising packets. This flag is effective only in extended advertising.
* Default value: 1
*     
*
**/

static inline struct gecko_msg_le_gap_set_advertise_configuration_rsp_t* gecko_cmd_le_gap_set_advertise_configuration(uint8 handle,uint32 configurations)
{
    if(ENDIAN) reverse_endian((uint8*)&configurations,4);
    
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_configuration.handle=handle;
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_configuration.configurations=configurations;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_advertise_configuration_id+((5)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_advertise_configuration;
}

/** 
*
* gecko_cmd_le_gap_clear_advertise_configuration
*
* This command can be used to disable advertising configurations on the given advertising set. The command "le_gap_set_advertise_configuration" can be used to set configurations. This setting will take effect on the next advertising enabling. 
*
* @param handle   Advertising set handle
* @param configurations   Advertising configuration flags to disable. This value can be a bitmask of multiple flags. See "le_gap_set_advertise_configuration" for possible flags.                     
*
**/

static inline struct gecko_msg_le_gap_clear_advertise_configuration_rsp_t* gecko_cmd_le_gap_clear_advertise_configuration(uint8 handle,uint32 configurations)
{
    if(ENDIAN) reverse_endian((uint8*)&configurations,4);
    
    gecko_cmd_msg->data.cmd_le_gap_clear_advertise_configuration.handle=handle;
    gecko_cmd_msg->data.cmd_le_gap_clear_advertise_configuration.configurations=configurations;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_clear_advertise_configuration_id+((5)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_clear_advertise_configuration;
}

/** 
*
* gecko_cmd_le_gap_start_advertising
*
* This command can be used to start the advertising of the given advertising set with specified discoverable and connectable modes.             
* The number of concurrent connectable advertisings is also limited by
* MAX_CONNECTIONS configuration. For example, only one connectable
* advertising can be enabled if the device has (MAX_CONNECTIONS - 1)
* connections when this command is called. The limitation does not apply
* to non-connectable advertising.
* The default advertising configuration in the stack is set to using
* legacy advertising PDUs on LE 1M PHY. The stack will automatically
* select extended advertising PDUs if either of the followings has
* occurred under the default configuration:
*  - The connectable mode is set to le_gap_connectable_non_scannable.
*  - The primary advertising PHY has been set to LE Coded PHY by command "le_gap_set_advertise_phy".
* If currently set parameters can't be used then an error will be
* returned. Specifically, this command fails with "Connection Limit
* Exceeded" error if it may cause the number of connections exceeding
* the configured MAX_CONNECTIONS value. It fails with "Invalid
* Parameter" error if one of the following cases occur:
*  - Non-resolvable random address is used but the connectable mode is le_gap_connectable_scannable or le_gap_connectable_non_scannable.
*  - The connectable mode is le_gap_connectable_non_scannable, but using legacy advertising PDUs has been explicitly enabled with command "le_gap_set_advertise_configuration".
*  - The primary advertising PHY is LE Coded PHY but using legacy advertising PDUs has been explicitly enabled with command "le_gap_set_advertise_configuration".
*  - The connectable mode is le_gap_connectable_scannable but using extended advertising PDUs has been explicitly enabled or the primary advertising PHY has been set to LE Coded PHY.
* If advertising will be enabled in user_data mode,
* "le_gap_bt5_set_adv_data" should be used to set advertising and scan
* response data before issuing this command. When the advertising is
* enabled in other modes than user_data, the advertising and scan
* response data is generated by the stack using the following procedure:
*  - Add a Flags field to advertising data.
*  - Add a TX power level field to advertising data if TX power service exists in the local GATT database.
*  - Add a Slave Connection Interval Range field to advertising data if the GAP peripheral preferred connection parameters characteristic exists in the local GATT database.
*  - Add a list of 16-bit Service UUIDs to advertising data if there are one or more 16-bit service UUIDs to advertise. The list is complete if all advertised 16-bit UUIDs are in advertising data; otherwise the list is incomplete.
*  - Add a list of 128-bit service UUIDs to advertising data if there are one or more 128-bit service UUIDs to advertise and there is still free space for this field. The list is complete if all advertised 128-bit UUIDs are in advertising data; otherwise the list is incomplete. Note that an advertising data packet can contain at most one 128-bit service UUID.
*  - Try to add the full local name to advertising data if device is not in privacy mode. In case the full local name does not fit into the remaining free space, the advertised name is a shortened version by cutting off the end if the free space has at least 6 bytes; Otherwise, the local name is added to scan response data.
* Event "le_connection_opened" will be received when a remote device
* opens a connection to the advertiser on this advertising set.
*  
*
* @param handle   Advertising set handle
* @param discover   Discoverable mode
* @param connect   Connectable mode
*
* Events generated
*
* gecko_evt_le_gap_adv_timeout - Triggered when the number of advertising events set by this command has been done and advertising is stopped on the given advertising set.
* gecko_evt_le_connection_opened - Triggered when a remote device opened a connection to the advertiser on the specified advertising set.    
*
**/

static inline struct gecko_msg_le_gap_start_advertising_rsp_t* gecko_cmd_le_gap_start_advertising(uint8 handle,uint8 discover,uint8 connect)
{
    
    gecko_cmd_msg->data.cmd_le_gap_start_advertising.handle=handle;
    gecko_cmd_msg->data.cmd_le_gap_start_advertising.discover=discover;
    gecko_cmd_msg->data.cmd_le_gap_start_advertising.connect=connect;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_start_advertising_id+((3)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_le_gap_start_advertising_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_le_gap_start_advertising;
}

/** 
*
* gecko_cmd_le_gap_stop_advertising
*
* This command can be used to stop the advertising of the given advertising set.              
*
* @param handle   Advertising set handle    
*
**/

static inline struct gecko_msg_le_gap_stop_advertising_rsp_t* gecko_cmd_le_gap_stop_advertising(uint8 handle)
{
    
    gecko_cmd_msg->data.cmd_le_gap_stop_advertising.handle=handle;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_stop_advertising_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_le_gap_stop_advertising_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_le_gap_stop_advertising;
}

/** 
*
* gecko_cmd_le_gap_set_discovery_timing
*
* This command can be used to set the timing parameters of the specified PHYs. If the device is currently scanning for advertising devices the PHYs, new parameters will take effect when the scanning is restarted. 
*
* @param phys   The PHYs for which the parameters are set. 
*  - 1: LE 1M PHY
*  - 4: LE Coded PHY
*  - 5: LE 1M PHY and LE Coded PHY
* 
* @param scan_interval   Scan interval. This is defined as the time interval from when the device started its last scan until it begins the subsequent scan, that is how often to scan
*  - Time = Value x 0.625 ms
*  - Range: 0x0004 to 0xFFFF
*  - Time Range: 2.5 ms to 40.96 s
* Default value: 10 ms 
* There is a variable delay when switching channels at the end of each
* scanning interval which is included in the scanning interval time
* itself. During this switch time no advertising packets will be
* received by the device. The switch time variation is dependent on use
* case, for example in case of scanning while keeping active connections
* the channel switch time might be longer than when only scanning
* without any active connections. Increasing the scanning interval will
* reduce the amount of time in which the device cannot receive
* advertising packets as it will switch channels less often.
* After every scan interval the scanner will change the frequency it
* operates at. It will cycle through all the three advertising channels
* in a round robin fashion. According to the specification all three
* channels must be used by a scanner.
* 
* @param scan_window   Scan window. The duration of the scan. scan_window shall be less than or equal to scan_interval
*  - Time = Value x 0.625 ms
*  - Range: 0x0004 to 0xFFFF
*  - Time Range: 2.5 ms to 40.96 s
* Default value: 10 ms Note that packet reception is aborted if it has been started before scan window ends.     
*
**/

static inline struct gecko_msg_le_gap_set_discovery_timing_rsp_t* gecko_cmd_le_gap_set_discovery_timing(uint8 phys,uint16 scan_interval,uint16 scan_window)
{
    if(ENDIAN) reverse_endian((uint8*)&scan_interval,2);
    if(ENDIAN) reverse_endian((uint8*)&scan_window,2);
    
    gecko_cmd_msg->data.cmd_le_gap_set_discovery_timing.phys=phys;
    gecko_cmd_msg->data.cmd_le_gap_set_discovery_timing.scan_interval=scan_interval;
    gecko_cmd_msg->data.cmd_le_gap_set_discovery_timing.scan_window=scan_window;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_discovery_timing_id+((5)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_le_gap_set_discovery_timing_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_le_gap_set_discovery_timing;
}

/** 
*
* gecko_cmd_le_gap_set_discovery_type
*
* This command can be used to set the scan type of the specified PHYs. If the device is currently scanning for advertising devices on the PHYs, new parameters will take effect when the scanning is restarted 
*
* @param phys   The PHYs for which the parameters are set. 
*  - 1: LE 1M PHY
*  - 4: LE Coded PHY
*  - 5: LE 1M PHY and LE Coded PHY
* 
* @param scan_type   Scan type indicated by a flag. Values:
*  - 0: Passive scanning
*  - 1: Active scanning
*  - In passive scanning mode the device only listens to advertising packets and will not transmit any packet
*  - In active scanning mode the device will send out a scan request packet upon receiving advertising packet from a remote device and then it will listen to the scan response packet from remote device
* Default value: 0                     
*
**/

static inline struct gecko_msg_le_gap_set_discovery_type_rsp_t* gecko_cmd_le_gap_set_discovery_type(uint8 phys,uint8 scan_type)
{
    
    gecko_cmd_msg->data.cmd_le_gap_set_discovery_type.phys=phys;
    gecko_cmd_msg->data.cmd_le_gap_set_discovery_type.scan_type=scan_type;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_discovery_type_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_le_gap_set_discovery_type_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_le_gap_set_discovery_type;
}

/** 
*
* gecko_cmd_le_gap_start_discovery
*
* This command can be used to start the GAP discovery procedure to scan
* for advertising devices on the specified scanning PHY, that is to
* perform a device discovery. To cancel an ongoing
* discovery process use the "le_gap_end_procedure" command.
* "Invalid Parameter" error will be returned if the scanning PHY value
* is invalid or the device does not support the PHY.
*  
*
* @param scanning_phy   The scanning PHY. Value: 
*  - 1: LE 1M PHY
*  - 4: LE Coded PHY
* 
* @param mode   Bluetooth discovery Mode. For values see link
*
* Events generated
*
* gecko_evt_le_gap_scan_response - Every time an advertising packet is received, this event is triggered. The packets are not filtered in any way, so multiple events will be                     received for every advertising device in range.    
*
**/

static inline struct gecko_msg_le_gap_start_discovery_rsp_t* gecko_cmd_le_gap_start_discovery(uint8 scanning_phy,uint8 mode)
{
    
    gecko_cmd_msg->data.cmd_le_gap_start_discovery.scanning_phy=scanning_phy;
    gecko_cmd_msg->data.cmd_le_gap_start_discovery.mode=mode;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_start_discovery_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return &gecko_rsp_msg->data.rsp_le_gap_start_discovery;
}

/** 
*
* gecko_cmd_le_gap_set_data_channel_classification
*
* This command can be used to specify a channel classification for data channels. This classification persists until overwritten with a subsequent command or until the system is reset. 
*
* @param channel_map   This parameter is 5 bytes and contains 37 1-bit fields.{br}                 The nth such field (in the range 0 to 36) contains the value for the link layer channel index n.{br}                 
*  - 0: Channel n is bad.
*  - 1:  Channel n is unknown.
* The most significant bits are reserved and shall be set to 0 for future use.{br}                 At least two channels shall be marked as unknown.                     
*
**/

static inline struct gecko_msg_le_gap_set_data_channel_classification_rsp_t* gecko_cmd_le_gap_set_data_channel_classification(uint8 channel_map_len, const uint8* channel_map_data)
{
    
    gecko_cmd_msg->data.cmd_le_gap_set_data_channel_classification.channel_map.len=channel_map_len;
    memcpy(gecko_cmd_msg->data.cmd_le_gap_set_data_channel_classification.channel_map.data,channel_map_data,channel_map_len);
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_data_channel_classification_id+((1+channel_map_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_data_channel_classification;
}

/** 
*
* gecko_cmd_le_gap_connect
*
* This command can be used to connect an advertising device with the
* specified initiating PHY.                 The Bluetooth stack will
* enter a state where it continuously                 scans for the
* connectable advertising packets from the remote                 device
* which matches the Bluetooth address given as a
* parameter. Scan parameters set in
* "le_gap_set_discovery_timing" are used in this operation.
* Upon receiving the advertising packet, the module                 will
* send a connection request packet to the target device to
* initiate a Bluetooth connection. To cancel an ongoing
* connection process use the "le_connection_close" command with the
* handle received in the response from this command.
* A connection is opened in no-security mode. If the GATT
* client needs to read or write the attributes on GATT server
* requiring encryption or authentication, it must first encrypt
* the connection using an appropriate authentication method.
* If a connection cannot be established at all for some reason (for
* example,                 the remote device has gone out of range, has
* entered into deep sleep, or                 is not advertising), the
* stack will try to connect forever.                 In this case the
* application will not get any event related to the connection request.
* To recover from this situation, application can implement a timeout
* and call                 "le_connection_close" to cancel the
* connection request.
* This command fails with "Connection Limit Exceeded" error if
* the number of connections attempted to be opened exceeds the
* configured MAX_CONNECTIONS value.
* This command fails with "Invalid Parameter" error if the initiating
* PHY value is invalid or the device does not support the PHY.
* Later calls of this command have to wait for the ongoing command                  to complete. A received event                   "le_connection_opened"                  indicates connection opened successfully and a received event                 "le_connection_closed"                  indicates connection failures have occurred.              
*
* @param address   Address of the device to connect to
* @param address_type   Address type of the device to connect to
* @param initiating_phy   The initiating PHY. Value: 
*  - 1: LE 1M PHY
*  - 4: LE Coded PHY
* 
*
* Events generated
*
* gecko_evt_le_connection_opened - This event is triggered after the connection has been opened, and indicates whether the devices are already bonded and what is the role of the Bluetooth device (Slave or Master).
* gecko_evt_le_connection_parameters - This event indicates the connection parameters and security mode of the connection.    
*
**/

static inline struct gecko_msg_le_gap_connect_rsp_t* gecko_cmd_le_gap_connect(bd_addr address,uint8 address_type,uint8 initiating_phy)
{
    
    memcpy(&gecko_cmd_msg->data.cmd_le_gap_connect.address,&address,sizeof(bd_addr));
    gecko_cmd_msg->data.cmd_le_gap_connect.address_type=address_type;
    gecko_cmd_msg->data.cmd_le_gap_connect.initiating_phy=initiating_phy;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_connect_id+((8)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_le_gap_connect_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_le_gap_connect;
}

/** 
*
* gecko_cmd_le_gap_set_advertise_tx_power
*
* This command can be used to limit the maximum advertising TX power on the given advertising set.                 If the value goes over the global value that has been set using                 "system_set_tx_power" command,                 the global value will be the maximum limit.                 The maximum TX power of legacy advertising is further constrainted to not go over +10 dBm.                 Extended advertising TX power can be +10 dBm and over if Adaptive Frequency Hopping has been enabled.                 
* This setting will take effect on the next advertising enabling.
* By default, maximum advertising TX power is limited by the global
* value.
*  
*
* @param handle   Advertising set handle
* @param power   TX power in 0.1dBm steps, for example the value of 10 is 1dBm and 55 is 5.5dBm    
*
**/

static inline struct gecko_msg_le_gap_set_advertise_tx_power_rsp_t* gecko_cmd_le_gap_set_advertise_tx_power(uint8 handle,int16 power)
{
    if(ENDIAN) reverse_endian((uint8*)&power,2);

    gecko_cmd_msg->data.cmd_le_gap_set_advertise_tx_power.handle=handle;
    gecko_cmd_msg->data.cmd_le_gap_set_advertise_tx_power.power=power;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_advertise_tx_power_id+((3)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_advertise_tx_power;
}

/** 
*
* gecko_cmd_le_gap_set_discovery_extended_scan_response
*
* This command can be used to enable and disable the extended scan response event.                 When the extended scan response event is enabled, it replaces "le_gap_scan_response",                 that is, the stack will generate either "le_gap_extended_scan_response"                 or "le_gap_scan_response", but not both at a time.              
*
* @param enable   Values: 
*  - 0: Disable extended scan response event
*  - 1: Enable extended scan response event
*     
*
**/

static inline struct gecko_msg_le_gap_set_discovery_extended_scan_response_rsp_t* gecko_cmd_le_gap_set_discovery_extended_scan_response(uint8 enable)
{
    
    gecko_cmd_msg->data.cmd_le_gap_set_discovery_extended_scan_response.enable=enable;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_set_discovery_extended_scan_response_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_set_discovery_extended_scan_response;
}

/** 
*
* gecko_cmd_le_gap_start_periodic_advertising
*
* This command can be used to start periodic advertising on the given advertising set.                 The stack will enable the advertising set automatically if the set has not been enabled                 and the set can advertise using extended advertising PDUs.                 
* "Invalid Parameter" error will be returned if the application has
* configured                 to use legacy advertising PDUs or anonymous
* advertising, or advertising set has been                 enabled using
* legacy advertising PDUs.
*  
*
* @param handle   Advertising set handle
* @param interval_min   Minimum periodic advertising interval. Value in units of 1.25 ms
*  - Range: 0x06 to 0xFFFF
*  - Time range: 7.5 ms to 81.92 s
* Default value: 100 ms
* @param interval_max   Maximum periodic advertising interval. Value in units of 1.25 ms
*  - Range: 0x06 to 0xFFFF
*  - Time range: 7.5 ms to 81.92 s
*  - Note: interval_max should be bigger than interval_min
* Default value: 200 ms
* @param flags   Periodic advertising configurations. Bitmask of followings:                     
*  - Bit 0: Include TX power in advertising PDU
*     
*
**/

static inline struct gecko_msg_le_gap_start_periodic_advertising_rsp_t* gecko_cmd_le_gap_start_periodic_advertising(uint8 handle,uint16 interval_min,uint16 interval_max,uint32 flags)
{
    if(ENDIAN) reverse_endian((uint8*)&interval_min,2);
    if(ENDIAN) reverse_endian((uint8*)&interval_max,2);
    if(ENDIAN) reverse_endian((uint8*)&flags,4);
    
    gecko_cmd_msg->data.cmd_le_gap_start_periodic_advertising.handle=handle;
    gecko_cmd_msg->data.cmd_le_gap_start_periodic_advertising.interval_min=interval_min;
    gecko_cmd_msg->data.cmd_le_gap_start_periodic_advertising.interval_max=interval_max;
    gecko_cmd_msg->data.cmd_le_gap_start_periodic_advertising.flags=flags;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_start_periodic_advertising_id+((9)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_start_periodic_advertising;
}

/** 
*
* gecko_cmd_le_gap_stop_periodic_advertising
*
* This command can be used to stop the periodic advertising on the given advertising set.             
* This command does not affect the enable state of the advertising set.
*  
*
* @param handle   Advertising set handle    
*
**/

static inline struct gecko_msg_le_gap_stop_periodic_advertising_rsp_t* gecko_cmd_le_gap_stop_periodic_advertising(uint8 handle)
{
    
    gecko_cmd_msg->data.cmd_le_gap_stop_periodic_advertising.handle=handle;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_stop_periodic_advertising_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_stop_periodic_advertising;
}

/** 
*
* gecko_cmd_le_gap_enable_whitelisting
*
* This command is used to enable whitelisting. To add devices to the whitelist either bond with the device or add it manually with "sm_add_to_whitelist" 
*
* @param enable   1 enable, 0 disable whitelisting.    
*
**/

static inline struct gecko_msg_le_gap_enable_whitelisting_rsp_t* gecko_cmd_le_gap_enable_whitelisting(uint8 enable)
{
    
    gecko_cmd_msg->data.cmd_le_gap_enable_whitelisting.enable=enable;
    gecko_cmd_msg->header=((gecko_cmd_le_gap_enable_whitelisting_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_gap_enable_whitelisting;
}

/** 
*
* gecko_cmd_sync_open
*
* This command can be used to establish a synchronization with periodic advertising from the specified             advertiser and begin receiving periodic advertising packets.          
*
* @param adv_sid   Advertising set identifier
* @param skip   The number of periodic advertising packets that can be skipped after a successful receive.                     Range: 0x0000 to 0x01F3                  
* @param timeout   Synchronization timeout for the periodic advertising. Unit: 10 ms.                      
*  - Range: 0x06 to 0xFFFF
*  - Unit: 10 ms
*  - Time range: 100 ms ms to 163.84 s
* 
* @param address   Address of the advertiser
* @param address_type   Advertiser address type. Values: 
*  - 0: Public address
*  - 1: Random address
* 
*
* Events generated
*
* gecko_evt_sync_opened - This event is triggered after the synchronization has been established.
* gecko_evt_sync_data - This event indicates a periodic advertising packet has been received.    
*
**/

static inline struct gecko_msg_sync_open_rsp_t* gecko_cmd_sync_open(uint8 adv_sid,uint16 skip,uint16 timeout,bd_addr address,uint8 address_type)
{
    if(ENDIAN) reverse_endian((uint8*)&skip,2);
    if(ENDIAN) reverse_endian((uint8*)&timeout,2);
    
    gecko_cmd_msg->data.cmd_sync_open.adv_sid=adv_sid;
    gecko_cmd_msg->data.cmd_sync_open.skip=skip;
    gecko_cmd_msg->data.cmd_sync_open.timeout=timeout;
    memcpy(&gecko_cmd_msg->data.cmd_sync_open.address,&address,sizeof(bd_addr));
    gecko_cmd_msg->data.cmd_sync_open.address_type=address_type;
    gecko_cmd_msg->header=((gecko_cmd_sync_open_id+((12)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sync_open;
}

/** 
*
* gecko_cmd_sync_close
*
* This command can be used to close a synchronization with periodic advertising or cancel an ongoing             synchronization establishment procedure.          
*
* @param sync   Periodic advertising synchronization handle
*
* Events generated
*
* gecko_evt_sync_closed - This event is triggered after the synchronization has been closed.    
*
**/

static inline struct gecko_msg_sync_close_rsp_t* gecko_cmd_sync_close(uint8 sync)
{
    
    gecko_cmd_msg->data.cmd_sync_close.sync=sync;
    gecko_cmd_msg->header=((gecko_cmd_sync_close_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sync_close;
}

/** 
*
* gecko_cmd_le_connection_set_parameters
*
* This command can be used to request a change in the connection parameters of a Bluetooth  connection. 
*
* @param connection   Connection Handle
* @param min_interval   Minimum value for the connection event interval. This must be set be less than or equal to max_interval.
*  - Time = Value x 1.25 ms
*  - Range: 0x0006 to 0x0c80
*  - Time Range: 7.5 ms to 4 s
* 
* @param max_interval   Maximum value for the connection event interval. This must be set greater than or equal to min_interval.
*  - Time = Value x 1.25 ms
*  - Range: 0x0006 to 0x0c80
*  - Time Range: 7.5 ms to 4 s
* 
* @param latency   Slave latency. This parameter defines how many connection intervals the slave can skip if it has no data to send
*  - Range: 0x0000 to 0x01f4
* Use 0x0000 for default value                 
* @param timeout   Supervision timeout. The supervision timeout defines for how long the connection is maintained despite the devices being unable to communicate at the currently configured  connection intervals.
*  - Range: 0x000a to 0x0c80
*  - Time = Value x 10 ms
*  - Time Range: 100 ms to 32 s
*  - The value in milliseconds must be larger than (1 + latency) * max_interval * 2, where max_interval is given in milliseconds
* It is recommended that the supervision timeout is set at a value which allows communication attempts over at least a few connection intervals.                 
*
* Events generated
*
* gecko_evt_le_connection_parameters - This event is triggered after new connection parameters has been applied on the connection.    
*
**/

static inline struct gecko_msg_le_connection_set_parameters_rsp_t* gecko_cmd_le_connection_set_parameters(uint8 connection,uint16 min_interval,uint16 max_interval,uint16 latency,uint16 timeout)
{
    if(ENDIAN) reverse_endian((uint8*)&min_interval,2);
    if(ENDIAN) reverse_endian((uint8*)&max_interval,2);
    if(ENDIAN) reverse_endian((uint8*)&latency,2);
    if(ENDIAN) reverse_endian((uint8*)&timeout,2);
    
    gecko_cmd_msg->data.cmd_le_connection_set_parameters.connection=connection;
    gecko_cmd_msg->data.cmd_le_connection_set_parameters.min_interval=min_interval;
    gecko_cmd_msg->data.cmd_le_connection_set_parameters.max_interval=max_interval;
    gecko_cmd_msg->data.cmd_le_connection_set_parameters.latency=latency;
    gecko_cmd_msg->data.cmd_le_connection_set_parameters.timeout=timeout;
    gecko_cmd_msg->header=((gecko_cmd_le_connection_set_parameters_id+((9)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_connection_set_parameters;
}

/** 
*
* gecko_cmd_le_connection_get_rssi
*
* This command can be used to get the latest RSSI value of a Bluetooth connection. 
*
* @param connection   Connection handle
*
* Events generated
*
* gecko_evt_le_connection_rssi - Triggered when this command has completed.    
*
**/

static inline struct gecko_msg_le_connection_get_rssi_rsp_t* gecko_cmd_le_connection_get_rssi(uint8 connection)
{
    
    gecko_cmd_msg->data.cmd_le_connection_get_rssi.connection=connection;
    gecko_cmd_msg->header=((gecko_cmd_le_connection_get_rssi_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_le_connection_get_rssi_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_le_connection_get_rssi;
}

/** 
*
* gecko_cmd_le_connection_disable_slave_latency
*
* This command temporarily enables or disables slave latency. Used only when Bluetooth device is in slave role. 
*
* @param connection   Connection Handle
* @param disable   0 enable, 1 disable slave latency    
*
**/

static inline struct gecko_msg_le_connection_disable_slave_latency_rsp_t* gecko_cmd_le_connection_disable_slave_latency(uint8 connection,uint8 disable)
{
    
    gecko_cmd_msg->data.cmd_le_connection_disable_slave_latency.connection=connection;
    gecko_cmd_msg->data.cmd_le_connection_disable_slave_latency.disable=disable;
    gecko_cmd_msg->header=((gecko_cmd_le_connection_disable_slave_latency_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_connection_disable_slave_latency;
}

/** 
*
* gecko_cmd_le_connection_set_phy
*
* This command can be used to set preferred PHYs for connection. Preferred PHYs are connection specific. Event "le_connection_phy_status" is received when PHY update procedure has been completed. Other than preferred PHY can also be set if remote device does not accept any of the preferred PHYs. 
* NOTE: 2 Mbit and Coded PHYs are not supported by all devices.
*  
*
* @param connection   
* @param phy   Preferred PHYs for connection. This parameter is bitfield and multiple PHYs can be preferred by setting multiple bits.                         
*  - 0x01: 1 Mbit PHY
*  - 0x02: 2 Mbit PHY
*  - 0x04: 125 kbit Coded PHY (S=8)
*  - 0x08: 500 kbit Coded PHY (S=2)
* 
*
* Events generated
*
* gecko_evt_le_connection_phy_status -     
*
**/

static inline struct gecko_msg_le_connection_set_phy_rsp_t* gecko_cmd_le_connection_set_phy(uint8 connection,uint8 phy)
{
    
    gecko_cmd_msg->data.cmd_le_connection_set_phy.connection=connection;
    gecko_cmd_msg->data.cmd_le_connection_set_phy.phy=phy;
    gecko_cmd_msg->header=((gecko_cmd_le_connection_set_phy_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_le_connection_set_phy;
}

/** 
*
* gecko_cmd_le_connection_close
*
* This command can be used to close a Bluetooth connection or cancel an ongoing                 connection establishment process. The parameter is a connection handle which is reported in "le_connection_opened" event or le_gap_connect response. 
*
* @param connection   Handle of the connection to be closed
*
* Events generated
*
* gecko_evt_le_connection_closed -     
*
**/

static inline struct gecko_msg_le_connection_close_rsp_t* gecko_cmd_le_connection_close(uint8 connection)
{
    
    gecko_cmd_msg->data.cmd_le_connection_close.connection=connection;
    gecko_cmd_msg->header=((gecko_cmd_le_connection_close_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_le_connection_close_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_le_connection_close;
}

/** 
*
* gecko_cmd_gatt_set_max_mtu
*
* This command can be used to set the maximum size of ATT Message Transfer Units (MTU). If the given value is too large according to the maximum BGAPI payload size, the system will select the maximal possible value as the maximum ATT_MTU. If maximum ATT_MTU is larger than 23, MTU is exchanged automatically after a Bluetooth connection has been established. 
*
* @param max_mtu   Maximum size of Message Transfer Units (MTU) allowed
*  - Range:  23 to 250
* Default: 247    
*
**/

static inline struct gecko_msg_gatt_set_max_mtu_rsp_t* gecko_cmd_gatt_set_max_mtu(uint16 max_mtu)
{
    if(ENDIAN) reverse_endian((uint8*)&max_mtu,2);
    
    gecko_cmd_msg->data.cmd_gatt_set_max_mtu.max_mtu=max_mtu;
    gecko_cmd_msg->header=((gecko_cmd_gatt_set_max_mtu_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_set_max_mtu;
}

/** 
*
* gecko_cmd_gatt_discover_primary_services
*
* This command can be used to discover all the primary services of a remote GATT database. This command generates a unique gatt_service event for              every discovered primary service. Received "gatt_procedure_completed" event indicates that this GATT procedure              has successfully completed or failed with error. 
*
* @param connection   
*
* Events generated
*
* gecko_evt_gatt_service - Discovered service from remote GATT database
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_discover_primary_services_rsp_t* gecko_cmd_gatt_discover_primary_services(uint8 connection)
{
    
    gecko_cmd_msg->data.cmd_gatt_discover_primary_services.connection=connection;
    gecko_cmd_msg->header=((gecko_cmd_gatt_discover_primary_services_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_gatt_discover_primary_services_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_gatt_discover_primary_services;
}

/** 
*
* gecko_cmd_gatt_discover_primary_services_by_uuid
*
* This command can be used to discover primary services with the specified UUID in a remote GATT database. This command generates unique gatt_service event for every discovered primary service. Received "gatt_procedure_completed" event indicates that this GATT procedure has succesfully completed or failed with error. 
*
* @param connection   
* @param uuid   Service UUID
*
* Events generated
*
* gecko_evt_gatt_service - Discovered service from remote GATT database.
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_discover_primary_services_by_uuid_rsp_t* gecko_cmd_gatt_discover_primary_services_by_uuid(uint8 connection,uint8 uuid_len, const uint8* uuid_data)
{    
    gecko_cmd_msg->data.cmd_gatt_discover_primary_services_by_uuid.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_discover_primary_services_by_uuid.uuid.len=uuid_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_discover_primary_services_by_uuid.uuid.data,uuid_data,uuid_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_discover_primary_services_by_uuid_id+((2+uuid_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_discover_primary_services_by_uuid;
}

/** 
*
* gecko_cmd_gatt_discover_characteristics
*
* This command can be used to discover all characteristics of the defined GATT service from a remote GATT database. This command generates a unique gatt_characteristic event for every discovered characteristic. Received "gatt_procedure_completed" event indicates that this GATT procedure has succesfully completed or failed with error. 
*
* @param connection   
* @param service   
*
* Events generated
*
* gecko_evt_gatt_characteristic - Discovered characteristic from remote GATT database.
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_discover_characteristics_rsp_t* gecko_cmd_gatt_discover_characteristics(uint8 connection,uint32 service)
{
    if(ENDIAN) reverse_endian((uint8*)&service,4);
    
    gecko_cmd_msg->data.cmd_gatt_discover_characteristics.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_discover_characteristics.service=service;
    gecko_cmd_msg->header=((gecko_cmd_gatt_discover_characteristics_id+((5)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_gatt_discover_characteristics_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_gatt_discover_characteristics;
}

/** 
*
* gecko_cmd_gatt_discover_characteristics_by_uuid
*
* This command can be used to discover all the characteristics of the specified GATT service in a remote GATT database having the specified UUID. This command generates a unique gatt_characteristic event for every discovered characteristic having the specified UUID. Received "gatt_procedure_completed" event indicates that this GATT procedure has successfully completed or failed with error.              
*
* @param connection   
* @param service   
* @param uuid   Characteristic UUID
*
* Events generated
*
* gecko_evt_gatt_characteristic - Discovered characteristic from remote GATT database.
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_discover_characteristics_by_uuid_rsp_t* gecko_cmd_gatt_discover_characteristics_by_uuid(uint8 connection,uint32 service,uint8 uuid_len, const uint8* uuid_data)
{
    if(ENDIAN) reverse_endian((uint8*)&service,4);
    
    gecko_cmd_msg->data.cmd_gatt_discover_characteristics_by_uuid.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_discover_characteristics_by_uuid.service=service;
    gecko_cmd_msg->data.cmd_gatt_discover_characteristics_by_uuid.uuid.len=uuid_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_discover_characteristics_by_uuid.uuid.data,uuid_data,uuid_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_discover_characteristics_by_uuid_id+((6+uuid_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_discover_characteristics_by_uuid;
}

/** 
*
* gecko_cmd_gatt_set_characteristic_notification
*
* This command can be used to enable or disable the notifications and indications being sent from a remote GATT server. This procedure discovers a              characteristic client configuration descriptor and writes the related configuration flags to a remote GATT database. A received "gatt_procedure_completed" event             indicates that this GATT procedure has successfully completed or that is has failed with an error. 
*
* @param connection   
* @param characteristic   
* @param flags   Characteristic client configuration flags
*
* Events generated
*
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.
* gecko_evt_gatt_characteristic_value - If an indication or notification has been enabled for a characteristic, this event is triggered                  whenever an indication or notification is sent by the remote GATT server. The triggering conditions on the GATT server side are defined by an                 upper level, for example by a profile; so it is possible that no values are ever received, or that it may take time, depending on how the server is configured.    
*
**/

static inline struct gecko_msg_gatt_set_characteristic_notification_rsp_t* gecko_cmd_gatt_set_characteristic_notification(uint8 connection,uint16 characteristic,uint8 flags)
{
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);
    
    gecko_cmd_msg->data.cmd_gatt_set_characteristic_notification.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_set_characteristic_notification.characteristic=characteristic;
    gecko_cmd_msg->data.cmd_gatt_set_characteristic_notification.flags=flags;
    gecko_cmd_msg->header=((gecko_cmd_gatt_set_characteristic_notification_id+((4)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_gatt_set_characteristic_notification_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_gatt_set_characteristic_notification;
}

/** 
*
* gecko_cmd_gatt_discover_descriptors
*
* This command can be used to discover all the descriptors of the specified remote GATT characteristics in a remote GATT database. This command generates a unique gatt_descriptor event for every discovered descriptor. Received "gatt_procedure_completed" event indicates that this GATT procedure has succesfully completed or failed with error. 
*
* @param connection   
* @param characteristic   
*
* Events generated
*
* gecko_evt_gatt_descriptor - Discovered descriptor from remote GATT database.
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_discover_descriptors_rsp_t* gecko_cmd_gatt_discover_descriptors(uint8 connection,uint16 characteristic)
{
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);
    
    gecko_cmd_msg->data.cmd_gatt_discover_descriptors.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_discover_descriptors.characteristic=characteristic;
    gecko_cmd_msg->header=((gecko_cmd_gatt_discover_descriptors_id+((3)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_discover_descriptors;
}

/** 
*
* gecko_cmd_gatt_read_characteristic_value
*
* This command can be used to read the value of a characteristic from a remote GATT database.              A single "gatt_characteristic_value" event is generated if the              characteristic value fits in one ATT PDU. Otherwise more than one "             gatt_characteristic_value" events are generated because the firmware will automatically use the "read long"              GATT procedure. A received "gatt_procedure_completed" event indicates             that all data has been read successfully or that an error response has been received.             
* Note that the GATT client does not verify if the requested atrribute
* is a characteristic value.             Thus before calling this
* command the application should make sure the attribute handle is for a
* characteristic             value in some means, for example, by
* performing characteristic discovery.
*  
*
* @param connection   
* @param characteristic   
*
* Events generated
*
* gecko_evt_gatt_characteristic_value - This event contains the data belonging to a characteristic sent by the GATT Server.
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_read_characteristic_value_rsp_t* gecko_cmd_gatt_read_characteristic_value(uint8 connection,uint16 characteristic)
{
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);
    
    gecko_cmd_msg->data.cmd_gatt_read_characteristic_value.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_read_characteristic_value.characteristic=characteristic;
    gecko_cmd_msg->header=((gecko_cmd_gatt_read_characteristic_value_id+((3)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_gatt_read_characteristic_value_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_gatt_read_characteristic_value;
}

/** 
*
* gecko_cmd_gatt_read_characteristic_value_by_uuid
*
* This command can be used to read the characteristic value of a service from a remote GATT database             by giving the UUID of the characteristic and the handle of the service containing this characteristic. A single             "gatt_characteristic_value" event is generated if the characteristic             value fits in one ATT PDU. Otherwise more than one "             gatt_characteristic_value" events are generated because the firmware will automatically use the "read long" GATT procedure.              A received "gatt_procedure_completed" event indicates that all data has been read successfully or that an error response has been received. 
*
* @param connection   
* @param service   
* @param uuid   Characteristic UUID
*
* Events generated
*
* gecko_evt_gatt_characteristic_value - This event contains the data belonging to a characteristic sent by the GATT Server.
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_read_characteristic_value_by_uuid_rsp_t* gecko_cmd_gatt_read_characteristic_value_by_uuid(uint8 connection,uint32 service,uint8 uuid_len, const uint8* uuid_data)
{
    if(ENDIAN) reverse_endian((uint8*)&service,4);

    gecko_cmd_msg->data.cmd_gatt_read_characteristic_value_by_uuid.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_read_characteristic_value_by_uuid.service=service;
    gecko_cmd_msg->data.cmd_gatt_read_characteristic_value_by_uuid.uuid.len=uuid_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_read_characteristic_value_by_uuid.uuid.data,uuid_data,uuid_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_read_characteristic_value_by_uuid_id+((6+uuid_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_read_characteristic_value_by_uuid;
}

/** 
*
* gecko_cmd_gatt_write_characteristic_value
*
* This command can be used to write the value of a characteristic in a remote GATT database. If the given value does not fit in one ATT PDU, "write long" GATT procedure is used automatically. Received              "gatt_procedure_completed" event indicates that all data has been written successfully or that an error response              has been received. 
*
* @param connection   
* @param characteristic   
* @param value   Characteristic value
*
* Events generated
*
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_write_characteristic_value_rsp_t* gecko_cmd_gatt_write_characteristic_value(uint8 connection,uint16 characteristic,uint8 value_len, const uint8* value_data)
{
    if ((uint16_t)value_len > BGLIB_MSG_MAX_PAYLOAD - 4)
    {
        gecko_rsp_msg->data.rsp_gatt_write_characteristic_value.result = bg_err_command_too_long;
        return &gecko_rsp_msg->data.rsp_gatt_write_characteristic_value;
    }
    
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);
    
    gecko_cmd_msg->data.cmd_gatt_write_characteristic_value.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_write_characteristic_value.characteristic=characteristic;
    gecko_cmd_msg->data.cmd_gatt_write_characteristic_value.value.len=value_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_write_characteristic_value.value.data,value_data,value_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_write_characteristic_value_id+((4+value_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_gatt_write_characteristic_value_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_gatt_write_characteristic_value;
}

/** 
*
* gecko_cmd_gatt_write_characteristic_value_without_response
*
* This command can be used to write the value of a characteristic in a             remote GATT server. This command does not generate any event. All failures on the server are ignored silently.              For example, if an error is generated in the remote GATT server and the given value is not written into database no error message will be reported to the local              GATT client. Note that this command cannot be used to write long values. At most ATT_MTU - 3 amount of data can be sent once. 
*
* @param connection   
* @param characteristic   
* @param value   Characteristic value    
*
**/

static inline struct gecko_msg_gatt_write_characteristic_value_without_response_rsp_t* gecko_cmd_gatt_write_characteristic_value_without_response(uint8 connection,uint16 characteristic,uint8 value_len, const uint8* value_data)
{
    if ((uint16_t)value_len > BGLIB_MSG_MAX_PAYLOAD - 4)
    {
        gecko_rsp_msg->data.rsp_gatt_write_characteristic_value_without_response.result = bg_err_command_too_long;
        return &gecko_rsp_msg->data.rsp_gatt_write_characteristic_value_without_response;
    }
    
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);
    
    gecko_cmd_msg->data.cmd_gatt_write_characteristic_value_without_response.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_write_characteristic_value_without_response.characteristic=characteristic;
    gecko_cmd_msg->data.cmd_gatt_write_characteristic_value_without_response.value.len=value_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_write_characteristic_value_without_response.value.data,value_data,value_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_write_characteristic_value_without_response_id+((4+value_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_gatt_write_characteristic_value_without_response_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_gatt_write_characteristic_value_without_response;
}

/** 
*
* gecko_cmd_gatt_prepare_characteristic_value_write
*
* This command can be used to add a characteristic value to the write
* queue of a remote GATT server.              This command can be used
* in cases where very long attributes need to be written, or a set of
* values needs to be written atomically. At most ATT_MTU - 5 amount of
* data can be sent once. Writes are executed or cancelled with the
* "execute_characteristic_value_write" command.             Whether the
* writes succeeded or not are indicated in the response of the
* "execute_characteristic_value_write" command.
* In all cases where the amount of data to transfer fits into the BGAPI
* payload the command              "gatt_write_characteristic_value" is
* recommended for writing long values since it transparently
* performs the prepare_write and execute_write commands.
*  
*
* @param connection   
* @param characteristic   
* @param offset   Offset of the characteristic value
* @param value   Value to write into the specified characteristic of the remote GATT database
*
* Events generated
*
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_prepare_characteristic_value_write_rsp_t* gecko_cmd_gatt_prepare_characteristic_value_write(uint8 connection,uint16 characteristic,uint16 offset,uint8 value_len, const uint8* value_data)
{
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);
    if(ENDIAN) reverse_endian((uint8*)&offset,2);
    
    gecko_cmd_msg->data.cmd_gatt_prepare_characteristic_value_write.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_prepare_characteristic_value_write.characteristic=characteristic;
    gecko_cmd_msg->data.cmd_gatt_prepare_characteristic_value_write.offset=offset;
    gecko_cmd_msg->data.cmd_gatt_prepare_characteristic_value_write.value.len=value_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_prepare_characteristic_value_write.value.data,value_data,value_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_prepare_characteristic_value_write_id+((6+value_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_prepare_characteristic_value_write;
}

/** 
*
* gecko_cmd_gatt_execute_characteristic_value_write
*
* This command can be used to commit or cancel previously queued writes to a long characteristic of a remote GATT server.             Writes are sent to queue with "prepare_characteristic_value_write" command.              Content, offset and length of queued values are validated by this procedure. A received "gatt_procedure_completed"             event indicates that all data has been written successfully or that an error response has been received.              
*
* @param connection   
* @param flags   
*
* Events generated
*
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_execute_characteristic_value_write_rsp_t* gecko_cmd_gatt_execute_characteristic_value_write(uint8 connection,uint8 flags)
{
    
    gecko_cmd_msg->data.cmd_gatt_execute_characteristic_value_write.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_execute_characteristic_value_write.flags=flags;
    gecko_cmd_msg->header=((gecko_cmd_gatt_execute_characteristic_value_write_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_execute_characteristic_value_write;
}

/** 
*
* gecko_cmd_gatt_send_characteristic_confirmation
*
* This command must be used to send a characteristic confirmation to a remote GATT server after receiving an indication.              The "gatt_characteristic_value_event" carries the att_opcode containing handle_value_indication (0x1d) which reveals              that an indication has been received and this must be confirmed with this command. Confirmation needs to be sent within 30 seconds, otherwise the GATT transactions              between the client and the server are discontinued. 
*
* @param connection       
*
**/

static inline struct gecko_msg_gatt_send_characteristic_confirmation_rsp_t* gecko_cmd_gatt_send_characteristic_confirmation(uint8 connection)
{
    
    gecko_cmd_msg->data.cmd_gatt_send_characteristic_confirmation.connection=connection;
    gecko_cmd_msg->header=((gecko_cmd_gatt_send_characteristic_confirmation_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_send_characteristic_confirmation;
}

/** 
*
* gecko_cmd_gatt_read_descriptor_value
*
* This command can be used to read the descriptor value of a characteristic in a remote GATT database. A single "             gatt_descriptor_value" event is generated if the descriptor value fits in one ATT PDU. Otherwise more than one "gatt_descriptor_value" events are generated because the firmware              will automatically use the "read long" GATT procedure. A received "gatt_procedure_completed" event indicates that all              data has been read successfully or that an error response has been received. 
*
* @param connection   
* @param descriptor   
*
* Events generated
*
* gecko_evt_gatt_descriptor_value - Descriptor value received from the remote GATT server.
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_read_descriptor_value_rsp_t* gecko_cmd_gatt_read_descriptor_value(uint8 connection,uint16 descriptor)
{
    if(ENDIAN) reverse_endian((uint8*)&descriptor,2);
    
    gecko_cmd_msg->data.cmd_gatt_read_descriptor_value.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_read_descriptor_value.descriptor=descriptor;
    gecko_cmd_msg->header=((gecko_cmd_gatt_read_descriptor_value_id+((3)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_read_descriptor_value;
}

/** 
*
* gecko_cmd_gatt_write_descriptor_value
*
* This command can be used to write the value of a characteristic descriptor in a remote GATT database. If the given value does not fit in one ATT PDU, "write long" GATT procedure is used automatically. Received "gatt_procedure_completed"              event indicates that all data has been written succesfully or that an error response has been received.              
*
* @param connection   
* @param descriptor   
* @param value   Descriptor value
*
* Events generated
*
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_write_descriptor_value_rsp_t* gecko_cmd_gatt_write_descriptor_value(uint8 connection,uint16 descriptor,uint8 value_len, const uint8* value_data)
{
    if(ENDIAN) reverse_endian((uint8*)&descriptor,2);

    
    gecko_cmd_msg->data.cmd_gatt_write_descriptor_value.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_write_descriptor_value.descriptor=descriptor;
    gecko_cmd_msg->data.cmd_gatt_write_descriptor_value.value.len=value_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_write_descriptor_value.value.data,value_data,value_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_write_descriptor_value_id+((4+value_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_write_descriptor_value;
}

/** 
*
* gecko_cmd_gatt_find_included_services
*
* This command can be used to find out if a service of a remote GATT database includes one or more other services. This command generates a unique gatt_service_completed event for each included service. This command generates a unique gatt_service event for every discovered service. Received "gatt_procedure_completed" event indicates that this GATT procedure has successfully completed or failed with error. 
*
* @param connection   
* @param service   
*
* Events generated
*
* gecko_evt_gatt_service - Discovered service from remote GATT database.
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_find_included_services_rsp_t* gecko_cmd_gatt_find_included_services(uint8 connection,uint32 service)
{
    if(ENDIAN) reverse_endian((uint8*)&service,4);
    
    gecko_cmd_msg->data.cmd_gatt_find_included_services.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_find_included_services.service=service;
    gecko_cmd_msg->header=((gecko_cmd_gatt_find_included_services_id+((5)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_find_included_services;
}

/** 
*
* gecko_cmd_gatt_read_multiple_characteristic_values
*
* This command can be used to read the values of multiple characteristics from a remote GATT database at once.              "gatt_characteristic_value" events are generated as the values are returned by the remote GATT server.             A received "gatt_procedure_completed" event indicates that either all data has been read successfully or that an error response has been received. 
*
* @param connection   
* @param characteristic_list   Little endian encoded uint16 list of characteristics to be read.
*
* Events generated
*
* gecko_evt_gatt_characteristic_value - This event contains the data belonging to a characteristic sent by the GATT Server.
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_read_multiple_characteristic_values_rsp_t* gecko_cmd_gatt_read_multiple_characteristic_values(uint8 connection,uint8 characteristic_list_len, const uint8* characteristic_list_data)
{ 
    gecko_cmd_msg->data.cmd_gatt_read_multiple_characteristic_values.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_read_multiple_characteristic_values.characteristic_list.len=characteristic_list_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_read_multiple_characteristic_values.characteristic_list.data,characteristic_list_data,characteristic_list_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_read_multiple_characteristic_values_id+((2+characteristic_list_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_read_multiple_characteristic_values;
}

/** 
*
* gecko_cmd_gatt_read_characteristic_value_from_offset
*
* This command can be used to read a partial characteristic value with specified offset and maximum length              from a remote GATT database. It is equivalent to             "gatt_read_characteristic_value"             if both the offset and maximum length parameters are 0.             A single "gatt_characteristic_value" event is generated              if the value to read fits in one ATT PDU. Otherwise more than one "             gatt_characteristic_value" events are generated because the firmware will automatically use the "read long"              GATT procedure. A received "gatt_procedure_completed" event indicates             that all data has been read successfully or that an error response has been received. 
*
* @param connection   
* @param characteristic   
* @param offset   Offset of the characteristic value
* @param maxlen   Maximum bytes to read. If this parameter is 0 all characteristic value starting at given offset will be read.                     
*
* Events generated
*
* gecko_evt_gatt_characteristic_value - This event contains the data belonging to a characteristic sent by the GATT Server.
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_read_characteristic_value_from_offset_rsp_t* gecko_cmd_gatt_read_characteristic_value_from_offset(uint8 connection,uint16 characteristic,uint16 offset,uint16 maxlen)
{
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);
    if(ENDIAN) reverse_endian((uint8*)&offset,2);
    if(ENDIAN) reverse_endian((uint8*)&maxlen,2);
    
    gecko_cmd_msg->data.cmd_gatt_read_characteristic_value_from_offset.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_read_characteristic_value_from_offset.characteristic=characteristic;
    gecko_cmd_msg->data.cmd_gatt_read_characteristic_value_from_offset.offset=offset;
    gecko_cmd_msg->data.cmd_gatt_read_characteristic_value_from_offset.maxlen=maxlen;
    gecko_cmd_msg->header=((gecko_cmd_gatt_read_characteristic_value_from_offset_id+((7)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_read_characteristic_value_from_offset;
}

/** 
*
* gecko_cmd_gatt_prepare_characteristic_value_reliable_write
*
* This command can be used to add a characteristic value to the write
* queue of a remote GATT server and verify if the value was correctly
* received by the server. Received "gatt_procedure_completed" event
* indicates that this GATT procedure has succesfully completed or failed
* with error. Specifically, error code 0x0194 (data_corrupted) will be
* returned if the value received from the GATT server's response failed
* to pass the reliable write verification. At most ATT_MTU - 5 amount of
* data can be sent once. Writes are executed or cancelled with the
* "execute_characteristic_value_write" command.             Whether the
* writes succeeded or not are indicated in the response of the
* "execute_characteristic_value_write" command.
*  
*
* @param connection   
* @param characteristic   
* @param offset   Offset of the characteristic value
* @param value   Value to write into the specified characteristic of the remote GATT database
*
* Events generated
*
* gecko_evt_gatt_procedure_completed - Procedure has been successfully completed or failed with error.    
*
**/

static inline struct gecko_msg_gatt_prepare_characteristic_value_reliable_write_rsp_t* gecko_cmd_gatt_prepare_characteristic_value_reliable_write(uint8 connection,uint16 characteristic,uint16 offset,uint8 value_len, const uint8* value_data)
{
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);
    if(ENDIAN) reverse_endian((uint8*)&offset,2);
    
    gecko_cmd_msg->data.cmd_gatt_prepare_characteristic_value_reliable_write.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_prepare_characteristic_value_reliable_write.characteristic=characteristic;
    gecko_cmd_msg->data.cmd_gatt_prepare_characteristic_value_reliable_write.offset=offset;
    gecko_cmd_msg->data.cmd_gatt_prepare_characteristic_value_reliable_write.value.len=value_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_prepare_characteristic_value_reliable_write.value.data,value_data,value_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_prepare_characteristic_value_reliable_write_id+((6+value_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_prepare_characteristic_value_reliable_write;
}

/** 
*
* gecko_cmd_gatt_server_read_attribute_value
*
* This command can be used to read the value of an attribute from a local GATT database. Only (maximum BGAPI payload size - 3) amount of data can be read once. The application can continue reading with increased offset value if it receives (maximum BGAPI payload size - 3) amount of data. 
*
* @param attribute   Attribute handle
* @param offset   Value offset    
*
**/

static inline struct gecko_msg_gatt_server_read_attribute_value_rsp_t* gecko_cmd_gatt_server_read_attribute_value(uint16 attribute,uint16 offset)
{
    if(ENDIAN) reverse_endian((uint8*)&attribute,2);
    if(ENDIAN) reverse_endian((uint8*)&offset,2);
    
    gecko_cmd_msg->data.cmd_gatt_server_read_attribute_value.attribute=attribute;
    gecko_cmd_msg->data.cmd_gatt_server_read_attribute_value.offset=offset;
    gecko_cmd_msg->header=((gecko_cmd_gatt_server_read_attribute_value_id+((4)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_server_read_attribute_value;
}

/** 
*
* gecko_cmd_gatt_server_read_attribute_type
*
* This command can be used to read the type of an attribute from a local GATT database. The type is a UUID, usually 16 or 128 bits long. 
*
* @param attribute   Attribute handle    
*
**/

static inline struct gecko_msg_gatt_server_read_attribute_type_rsp_t* gecko_cmd_gatt_server_read_attribute_type(uint16 attribute)
{
    if(ENDIAN) reverse_endian((uint8*)&attribute,2);
    
    gecko_cmd_msg->data.cmd_gatt_server_read_attribute_type.attribute=attribute;
    gecko_cmd_msg->header=((gecko_cmd_gatt_server_read_attribute_type_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_server_read_attribute_type;
}

/** 
*
* gecko_cmd_gatt_server_write_attribute_value
*
* This command can be used to write the value of an attribute in the local GATT database. Writing the value of a characteristic of the local GATT database              will not trigger notifications or indications to the remote GATT client in case such characteristic has property of indicate or notify and the client has enabled              notification or indication. Notifications and indications are sent to the remote GATT client using "             gatt_server_send_characteristic_notification" command. 
*
* @param attribute   Attribute handle
* @param offset   Value offset
* @param value   Value    
*
**/

static inline struct gecko_msg_gatt_server_write_attribute_value_rsp_t* gecko_cmd_gatt_server_write_attribute_value(uint16 attribute,uint16 offset,uint8 value_len, const uint8* value_data)
{
    if(ENDIAN) reverse_endian((uint8*)&attribute,2);
    if(ENDIAN) reverse_endian((uint8*)&offset,2);
    
    gecko_cmd_msg->data.cmd_gatt_server_write_attribute_value.attribute=attribute;
    gecko_cmd_msg->data.cmd_gatt_server_write_attribute_value.offset=offset;
    gecko_cmd_msg->data.cmd_gatt_server_write_attribute_value.value.len=value_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_server_write_attribute_value.value.data,value_data,value_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_server_write_attribute_value_id+((5+value_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_server_write_attribute_value;
}

/** 
*
* gecko_cmd_gatt_server_send_user_read_response
*
* This command must be used to send a response to a "user_read_request" event. The response needs to be sent within 30 second, otherwise no more GATT              transactions are allowed by the remote side. If attr_errorcode is set to 0 the characteristic value is sent to the remote GATT client in the normal way. Other attr_errorcode              values will cause the local GATT server to send an attribute protocol error response instead of the actual data.             At most ATT_MTU - 1 amount of data can be sent once. Client will continue reading by sending new read request with             increased offset value if it receives ATT_MTU - 1 amount of data. 
*
* @param connection   
* @param characteristic   
* @param att_errorcode   
* @param value   Characteristic value to send to the GATT client. Ignored if att_errorcode is not 0.    
*
**/

static inline struct gecko_msg_gatt_server_send_user_read_response_rsp_t* gecko_cmd_gatt_server_send_user_read_response(uint8 connection,uint16 characteristic,uint8 att_errorcode,uint8 value_len, const uint8* value_data)
{
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);
    
    gecko_cmd_msg->data.cmd_gatt_server_send_user_read_response.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_server_send_user_read_response.characteristic=characteristic;
    gecko_cmd_msg->data.cmd_gatt_server_send_user_read_response.att_errorcode=att_errorcode;
    gecko_cmd_msg->data.cmd_gatt_server_send_user_read_response.value.len=value_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_server_send_user_read_response.value.data,value_data,value_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_server_send_user_read_response_id+((5+value_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_server_send_user_read_response;
}

/** 
*
* gecko_cmd_gatt_server_send_user_write_response
*
* This command must be used to send a response to a "gatt_server_user_write_request" event when parameter att_opcode in the event is Write Request (see "att_opcode"). The response needs to be sent within 30 seconds, otherwise no more GATT              transactions are allowed by the remote side. If attr_errorcode is set to 0 the ATT protocol's write response is sent to indicate to the remote GATT client that              the write operation was processed successfully. Other values will cause the local GATT server to send an ATT protocol error response. 
*
* @param connection   
* @param characteristic   
* @param att_errorcode       
*
**/

static inline struct gecko_msg_gatt_server_send_user_write_response_rsp_t* gecko_cmd_gatt_server_send_user_write_response(uint8 connection,uint16 characteristic,uint8 att_errorcode)
{
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);
    
    gecko_cmd_msg->data.cmd_gatt_server_send_user_write_response.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_server_send_user_write_response.characteristic=characteristic;
    gecko_cmd_msg->data.cmd_gatt_server_send_user_write_response.att_errorcode=att_errorcode;
    gecko_cmd_msg->header=((gecko_cmd_gatt_server_send_user_write_response_id+((4)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_server_send_user_write_response;
}

/** 
*
* gecko_cmd_gatt_server_send_characteristic_notification
*
* This command can be used to send notifications or indications to one or more remote GATT clients. At most ATT_MTU - 3 amount of data can be sent once.             
* A notification or indication is sent only if the client has enabled
* it by setting the corresponding flag to the Client Characteristic
* Configuration descriptor. In case the Client Characteristic
* Configuration descriptor supports both notification and indication,
* the stack will always send a notification even when the client has
* enabled both.
* A new indication to a GATT client cannot be sent until an outstanding
* indication procedure with the same client has completed. The procedure
* is completed when a confirmation from the client has been received.
* The confirmation is indicated              by
* "gatt_server_characteristic_status event".
* Error bg_err_wrong_state is returned if the characteristic does not
* have notification property, or if the client has not enabled the
* notification.             The same applies to indication property, and
* in addition, bg_err_wrong_state is returned if an indication procedure
* with the same client is outstanding.
*  
*
* @param connection   Handle of the connection over which the notification or indication is sent. Values: 
*  - 0xff: Sends notification or indication to all connected devices.
*  - Other: Connection handle
* 
* @param characteristic   Characteristic handle
* @param value   Value to be notified or indicated    
*
**/

static inline struct gecko_msg_gatt_server_send_characteristic_notification_rsp_t* gecko_cmd_gatt_server_send_characteristic_notification(uint8 connection,uint16 characteristic,uint8 value_len, const uint8* value_data)
{
    if ((uint16_t)value_len > BGLIB_MSG_MAX_PAYLOAD - 4)
    {
        gecko_rsp_msg->data.rsp_gatt_server_send_characteristic_notification.result = bg_err_command_too_long;
        return &gecko_rsp_msg->data.rsp_gatt_server_send_characteristic_notification;
    }
    
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);

    gecko_cmd_msg->data.cmd_gatt_server_send_characteristic_notification.connection=connection;
    gecko_cmd_msg->data.cmd_gatt_server_send_characteristic_notification.characteristic=characteristic;
    gecko_cmd_msg->data.cmd_gatt_server_send_characteristic_notification.value.len=value_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_server_send_characteristic_notification.value.data,value_data,value_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_server_send_characteristic_notification_id+((4+value_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
	if((gecko_rsp_msg == NULL) || (BGLIB_MSG_ID(gecko_rsp_msg->header) != gecko_rsp_gatt_server_send_characteristic_notification_id))
    {
        return NULL;
    }

    return &gecko_rsp_msg->data.rsp_gatt_server_send_characteristic_notification;
}

/** 
*
* gecko_cmd_gatt_server_find_attribute
*
* This command can be used to find attributes of certain type from a local GATT database. Type is usually given as 16-bit or 128-bit UUID. 
*
* @param start   Search start handle
* @param type       
*
**/

static inline struct gecko_msg_gatt_server_find_attribute_rsp_t* gecko_cmd_gatt_server_find_attribute(uint16 start,uint8 type_len, const uint8* type_data)
{
    if(ENDIAN) reverse_endian((uint8*)&start,2);
    
    gecko_cmd_msg->data.cmd_gatt_server_find_attribute.start=start;
    gecko_cmd_msg->data.cmd_gatt_server_find_attribute.type.len=type_len;
    memcpy(gecko_cmd_msg->data.cmd_gatt_server_find_attribute.type.data,type_data,type_len);
    gecko_cmd_msg->header=((gecko_cmd_gatt_server_find_attribute_id+((3+type_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_server_find_attribute;
}

/** 
*
* gecko_cmd_gatt_server_set_capabilities
*
* This command can be used to set which capabilities should be enabled in the local GATT database. A service is visible to remote GATT clients if at least one of its capabilities has been enabled. The same applies to a characteristic and its attributes. Capability identifiers and their corresponding bit flag values can be found in the auto-generated database header file. See UG118 for how to declare capabilities in GATT database.                 
* Changing the capabilities of a database effectively causes a database
* change (attributes being added or removed) from a remote GATT client
* point of view. If the database has a Generic Attribute service and
* Service Changed characteristic, the stack will monitor local database
* change status and manage service changed indications for a GATT client
* that has enabled the indication configuration of the Service Changed
* characteristic.
*  
*
* @param caps   Bit flags of capabilities to enable. Value 0 sets the default database capabilities.
* @param reserved   Value 0 should be used on this reserved field. None-zero values are reserved for future, do not use now.    
*
**/

static inline struct gecko_msg_gatt_server_set_capabilities_rsp_t* gecko_cmd_gatt_server_set_capabilities(uint32 caps,uint32 reserved)
{
    if(ENDIAN) reverse_endian((uint8*)&caps,4);
    if(ENDIAN) reverse_endian((uint8*)&reserved,4);
    
    gecko_cmd_msg->data.cmd_gatt_server_set_capabilities.caps=caps;
    gecko_cmd_msg->data.cmd_gatt_server_set_capabilities.reserved=reserved;
    gecko_cmd_msg->header=((gecko_cmd_gatt_server_set_capabilities_id+((8)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_gatt_server_set_capabilities;
}

/** 
*
* gecko_cmd_hardware_set_soft_timer
*
* This command can be used to start a software timer. Multiple concurrent timers can be running simultaneously. There are 256 unique timer IDs available.             The maximum number of concurrent timers is configurable at device initialization. Up to 16 concurrent timers can be configured. The default configuration is 4. As the RAM for storing timer data is pre-allocated at initialization, an application should not configure the amount more than it needs for minimizing RAM usage. 
*
* @param time   Interval between how often to send events, in hardware clock ticks (1 second is equal to 32768 ticks).                 
* The smallest interval value supported is 328 which is around 10
* milliseconds, any parameters between 0 and 328 will be rounded up to
* 328.                 The maximum value is 2147483647, which
* corresponds to about 18.2 hours.
* If time is 0, removes the scheduled timer with the same handle.
* @param handle   Timer handle to use, is returned in timeout event
* @param single_shot   Timer mode. Values: 
*  - 0: false (timer is repeating)
*  - 1: true (timer runs only once)
* 
*
* Events generated
*
* gecko_evt_hardware_soft_timer - Sent after specified interval    
*
**/

static inline struct gecko_msg_hardware_set_soft_timer_rsp_t* gecko_cmd_hardware_set_soft_timer(uint32 time,uint8 handle,uint8 single_shot)
{
    if(ENDIAN) reverse_endian((uint8*)&time,4);
    
    gecko_cmd_msg->data.cmd_hardware_set_soft_timer.time=time;
    gecko_cmd_msg->data.cmd_hardware_set_soft_timer.handle=handle;
    gecko_cmd_msg->data.cmd_hardware_set_soft_timer.single_shot=single_shot;
    gecko_cmd_msg->header=((gecko_cmd_hardware_set_soft_timer_id+((6)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_hardware_set_soft_timer;
}

/** 
*
* gecko_cmd_hardware_get_time
*
* Deprecated. Get elapsed time since last reset of RTCC 
*    
*
**/

static inline struct gecko_msg_hardware_get_time_rsp_t* gecko_cmd_hardware_get_time()
{
    
    gecko_cmd_msg->header=((gecko_cmd_hardware_get_time_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_hardware_get_time;
}

/** 
*
* gecko_cmd_hardware_set_lazy_soft_timer
*
* This command can be used to start a software timer with some slack. Slack parameter allows stack to optimize wake ups and save power. Timer event is triggered between time and time + slack. See also description of "hardware_set_soft_timer" command. 
*
* @param time   Interval between how often to send events, in hardware clock ticks (1 second is equal to 32768 ticks).                 
* The smallest interval value supported is 328 which is around 10
* milliseconds, any parameters between 0 and 328 will be rounded up to
* 328.                 The maximum value is 2147483647, which
* corresponds to about 18.2 hours.
* If time is 0, removes the scheduled timer with the same handle.
* @param slack   Slack time in hardware clock ticks
* @param handle   Timer handle to use, is returned in timeout event
* @param single_shot   Timer mode. Values: 
*  - 0: false (timer is repeating)
*  - 1: true (timer runs only once)
* 
*
* Events generated
*
* gecko_evt_hardware_soft_timer - Sent after specified interval    
*
**/

static inline struct gecko_msg_hardware_set_lazy_soft_timer_rsp_t* gecko_cmd_hardware_set_lazy_soft_timer(uint32 time,uint32 slack,uint8 handle,uint8 single_shot)
{
    if(ENDIAN) reverse_endian((uint8*)&time,4);
    if(ENDIAN) reverse_endian((uint8*)&slack,4);
    
    gecko_cmd_msg->data.cmd_hardware_set_lazy_soft_timer.time=time;
    gecko_cmd_msg->data.cmd_hardware_set_lazy_soft_timer.slack=slack;
    gecko_cmd_msg->data.cmd_hardware_set_lazy_soft_timer.handle=handle;
    gecko_cmd_msg->data.cmd_hardware_set_lazy_soft_timer.single_shot=single_shot;
    gecko_cmd_msg->header=((gecko_cmd_hardware_set_lazy_soft_timer_id+((10)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_hardware_set_lazy_soft_timer;
}

/** 
*
* gecko_cmd_flash_ps_erase_all
*
* This command can be used to erase all PS keys and their corresponding values. 
*    
*
**/

static inline struct gecko_msg_flash_ps_erase_all_rsp_t* gecko_cmd_flash_ps_erase_all()
{
    
    gecko_cmd_msg->header=((gecko_cmd_flash_ps_erase_all_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_flash_ps_erase_all;
}

/** 
*
* gecko_cmd_flash_ps_save
*
* This command can be used to store a value into the specified PS key. Allowed PS keys are in range from 0x4000 to 0x407F. At most 56 bytes user data can be stored in one PS key. Error code 0x018a (command_too_long) will be returned if more than 56 bytes data is passed in. 
*
* @param key   PS key
* @param value   Value to store into the specified PS key.    
*
**/

static inline struct gecko_msg_flash_ps_save_rsp_t* gecko_cmd_flash_ps_save(uint16 key,uint8 value_len, const uint8* value_data)
{
    if(ENDIAN) reverse_endian((uint8*)&key,2);
    
    gecko_cmd_msg->data.cmd_flash_ps_save.key=key;
    gecko_cmd_msg->data.cmd_flash_ps_save.value.len=value_len;
    memcpy(gecko_cmd_msg->data.cmd_flash_ps_save.value.data,value_data,value_len);
    gecko_cmd_msg->header=((gecko_cmd_flash_ps_save_id+((3+value_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_flash_ps_save;
}

/** 
*
* gecko_cmd_flash_ps_load
*
* This command can be used for retrieving the value of the specified PS key. 
*
* @param key   PS key of the value to be retrieved    
*
**/

static inline struct gecko_msg_flash_ps_load_rsp_t* gecko_cmd_flash_ps_load(uint16 key)
{
    if(ENDIAN) reverse_endian((uint8*)&key,2);
    
    gecko_cmd_msg->data.cmd_flash_ps_load.key=key;
    gecko_cmd_msg->header=((gecko_cmd_flash_ps_load_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_flash_ps_load;
}

/** 
*
* gecko_cmd_flash_ps_erase
*
* This command can be used to erase a single PS key and its value from the persistent store.. 
*
* @param key   PS key to erase    
*
**/

static inline struct gecko_msg_flash_ps_erase_rsp_t* gecko_cmd_flash_ps_erase(uint16 key)
{
    if(ENDIAN) reverse_endian((uint8*)&key,2);
    
    gecko_cmd_msg->data.cmd_flash_ps_erase.key=key;
    gecko_cmd_msg->header=((gecko_cmd_flash_ps_erase_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_flash_ps_erase;
}

/** 
*
* gecko_cmd_test_dtm_tx
*
* This command can be used to start a transmitter test. The test is meant to be used against a separate Bluetooth tester device. When the command is processed by the radio, a "test_dtm_completed" event is triggered. This event indicates if the test started successfully.                  
* In the transmitter test, the device sends packets continuously with a
* fixed interval. The type and length of each packet is set by
* packet_type and length parameters. Parameter phy specifies which PHY is used to transmit the packets. All devices support at least the 1M PHY. There is also a special packet type, test_pkt_carrier, which can be used to transmit continuous unmodulated carrier. The length field is ignored in this mode.
* The test may be stopped using the "test_dtm_end" command.
*  
*
* @param packet_type   Packet type to transmit
* @param length   Packet length in bytes
* Range: 0-255
* 
* @param channel   Bluetooth channel
* Range: 0-39
* Channel is (F - 2402) / 2,
* where F is frequency in MHz
* 
* @param phy   PHY to use
*
* Events generated
*
* gecko_evt_test_dtm_completed - This event is received when the command is processed.    
*
**/

static inline struct gecko_msg_test_dtm_tx_rsp_t* gecko_cmd_test_dtm_tx(uint8 packet_type,uint8 length,uint8 channel,uint8 phy)
{
    
    gecko_cmd_msg->data.cmd_test_dtm_tx.packet_type=packet_type;
    gecko_cmd_msg->data.cmd_test_dtm_tx.length=length;
    gecko_cmd_msg->data.cmd_test_dtm_tx.channel=channel;
    gecko_cmd_msg->data.cmd_test_dtm_tx.phy=phy;
    gecko_cmd_msg->header=((gecko_cmd_test_dtm_tx_id+((4)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_test_dtm_tx;
}

/** 
*
* gecko_cmd_test_dtm_rx
*
* This command can be used to start a receiver test. The test is meant to be used against a separate Bluetooth tester device. When the command is processed by the radio, a "test_dtm_completed" event is triggered. This event indicates if the test started successfully.                  
* Parameter
* phy specifies which PHY is used to receive the packets. All devices support at least the 1M PHY.
* The test may be stopped using the "test_dtm_end" command. This will
* trigger another "test_dtm_completed" event, which carries the number
* of packets received during the test.
*  
*
* @param channel   Bluetooth channel
* Range: 0-39
* Channel is (F - 2402) / 2,
* where F is frequency in MHz
* 
* @param phy   PHY to use
*
* Events generated
*
* gecko_evt_test_dtm_completed - This event is received when the command is processed.    
*
**/

static inline struct gecko_msg_test_dtm_rx_rsp_t* gecko_cmd_test_dtm_rx(uint8 channel,uint8 phy)
{
    
    gecko_cmd_msg->data.cmd_test_dtm_rx.channel=channel;
    gecko_cmd_msg->data.cmd_test_dtm_rx.phy=phy;
    gecko_cmd_msg->header=((gecko_cmd_test_dtm_rx_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_test_dtm_rx;
}

/** 
*
* gecko_cmd_test_dtm_end
*
* This command can be used to end a transmitter or a receiver test. When the command is processed by the radio and the test has ended, a "test_dtm_completed" event is triggered.              
*
*
* Events generated
*
* gecko_evt_test_dtm_completed - This event is received when the command is processed.    
*
**/

static inline struct gecko_msg_test_dtm_end_rsp_t* gecko_cmd_test_dtm_end()
{
    
    gecko_cmd_msg->header=((gecko_cmd_test_dtm_end_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_test_dtm_end;
}

/** 
*
* gecko_cmd_sm_set_bondable_mode
*
* This command can be used to set whether the device should accept new bondings. By default, the device does not accept new bondings. 
*
* @param bondable   Bondable mode. Values:                    
*  - 0: New bondings not accepted
*  - 1: Bondings allowed
* Default value: 0
*     
*
**/

static inline struct gecko_msg_sm_set_bondable_mode_rsp_t* gecko_cmd_sm_set_bondable_mode(uint8 bondable)
{
    
    gecko_cmd_msg->data.cmd_sm_set_bondable_mode.bondable=bondable;
    gecko_cmd_msg->header=((gecko_cmd_sm_set_bondable_mode_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_set_bondable_mode;
}

/** 
*
* gecko_cmd_sm_configure
*
* This command can be used to configure security requirements and I/O capabilities of the system. 
*
* @param flags   Security requirement bitmask.{br}Bit 0: 
*  - 0: Allow bonding without MITM protection
*  - 1: Bonding requires MITM protection
* Bit 1: 
*  - 0: Allow encryption without bonding
*  - 1: Encryption requires bonding. Note that this setting will also enable bonding.
* Bit 2: 
*  - 0: Allow bonding with legacy pairing
*  - 1: Secure connections only
* Bit 3: 
*  - 0: Bonding request does not need to be confirmed
*  - 1: Bonding requests need to be confirmed. Received bonding requests are notified with "sm_confirm_bonding events."
* Bit 4 to 7: Reserved{br}{br}Default value: 0x00
* @param io_capabilities   I/O Capabilities. See link    
*
**/

static inline struct gecko_msg_sm_configure_rsp_t* gecko_cmd_sm_configure(uint8 flags,uint8 io_capabilities)
{
    
    gecko_cmd_msg->data.cmd_sm_configure.flags=flags;
    gecko_cmd_msg->data.cmd_sm_configure.io_capabilities=io_capabilities;
    gecko_cmd_msg->header=((gecko_cmd_sm_configure_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_configure;
}

/** 
*
* gecko_cmd_sm_store_bonding_configuration
*
* This command can be used to set maximum allowed bonding count and bonding policy. The default value is maximum number of bondings supported. 
*
* @param max_bonding_count   Maximum allowed bonding count. Range: 1 to 14
* @param policy_flags   Bonding policy. Values: 
*  - 0: If database is full, new bonding attempts will fail
*  - 1: New bonding will overwrite the oldest existing bonding
*  - 2: New bonding will overwrite longest time ago used existing bonding
*     
*
**/

static inline struct gecko_msg_sm_store_bonding_configuration_rsp_t* gecko_cmd_sm_store_bonding_configuration(uint8 max_bonding_count,uint8 policy_flags)
{
    
    gecko_cmd_msg->data.cmd_sm_store_bonding_configuration.max_bonding_count=max_bonding_count;
    gecko_cmd_msg->data.cmd_sm_store_bonding_configuration.policy_flags=policy_flags;
    gecko_cmd_msg->header=((gecko_cmd_sm_store_bonding_configuration_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_store_bonding_configuration;
}

/** 
*
* gecko_cmd_sm_increase_security
*
* This command can be used to enhance the security of a connection to current security requirements. On an unencrypted connection, this will encrypt the connection and will also perform bonding if requested by both devices. On an encrypted connection, this will cause the connection re-encrypted. 
*
* @param connection   Connection handle
*
* Events generated
*
* gecko_evt_le_connection_parameters - This event is triggered after increasing security has been completed successfully, and indicates the latest security mode of the connection.
* gecko_evt_sm_bonded - This event is triggered if pairing or bonding was performed in this operation and the result is success.
* gecko_evt_sm_bonding_failed - This event is triggered if pairing or bonding was performed in this operation and the result is failure.    
*
**/

static inline struct gecko_msg_sm_increase_security_rsp_t* gecko_cmd_sm_increase_security(uint8 connection)
{
    
    gecko_cmd_msg->data.cmd_sm_increase_security.connection=connection;
    gecko_cmd_msg->header=((gecko_cmd_sm_increase_security_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_increase_security;
}

/** 
*
* gecko_cmd_sm_delete_bonding
*
* This command can be used to delete specified bonding information or whitelist from Persistent Store. 
*
* @param bonding   Bonding handle    
*
**/

static inline struct gecko_msg_sm_delete_bonding_rsp_t* gecko_cmd_sm_delete_bonding(uint8 bonding)
{
    
    gecko_cmd_msg->data.cmd_sm_delete_bonding.bonding=bonding;
    gecko_cmd_msg->header=((gecko_cmd_sm_delete_bonding_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_delete_bonding;
}

/** 
*
* gecko_cmd_sm_delete_bondings
*
* This command can be used to delete all bonding information and whitelist from Persistent Store. 
*    
*
**/

static inline struct gecko_msg_sm_delete_bondings_rsp_t* gecko_cmd_sm_delete_bondings()
{
    
    gecko_cmd_msg->header=((gecko_cmd_sm_delete_bondings_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_delete_bondings;
}

/** 
*
* gecko_cmd_sm_enter_passkey
*
* This command can be used to enter a passkey after receiving a passkey request event. 
*
* @param connection   Connection handle
* @param passkey   Passkey. Valid range: 0-999999. Set -1 to cancel pairing.    
*
**/

static inline struct gecko_msg_sm_enter_passkey_rsp_t* gecko_cmd_sm_enter_passkey(uint8 connection,int32 passkey)
{
    if(ENDIAN) reverse_endian((uint8*)&passkey,4);

    gecko_cmd_msg->data.cmd_sm_enter_passkey.connection=connection;
    gecko_cmd_msg->data.cmd_sm_enter_passkey.passkey=passkey;
    gecko_cmd_msg->header=((gecko_cmd_sm_enter_passkey_id+((5)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_enter_passkey;
}

/** 
*
* gecko_cmd_sm_passkey_confirm
*
* This command can be used for accepting or rejecting reported confirm value. 
*
* @param connection   Connection handle
* @param confirm   Accept confirm value. Values:
*  - 0: Reject
*  - 1: Accept confirm value
*     
*
**/

static inline struct gecko_msg_sm_passkey_confirm_rsp_t* gecko_cmd_sm_passkey_confirm(uint8 connection,uint8 confirm)
{
    
    gecko_cmd_msg->data.cmd_sm_passkey_confirm.connection=connection;
    gecko_cmd_msg->data.cmd_sm_passkey_confirm.confirm=confirm;
    gecko_cmd_msg->header=((gecko_cmd_sm_passkey_confirm_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_passkey_confirm;
}

/** 
*
* gecko_cmd_sm_set_oob_data
*
* This command can be used to set the OOB data (out-of-band encryption data) for legacy pairing for a device. The OOB data may be, for example, a PIN code exchanged over                  an alternate path like NFC. The device will not allow any other kind of bonding if OOB data is set. The OOB data cannot be set simultaneously with secure connections OOB data.               
*
* @param oob_data   OOB data. To set OOB data, send a 16-byte array. To clear OOB data, send a zero-length array.    
*
**/

static inline struct gecko_msg_sm_set_oob_data_rsp_t* gecko_cmd_sm_set_oob_data(uint8 oob_data_len, const uint8* oob_data_data)
{
    
    gecko_cmd_msg->data.cmd_sm_set_oob_data.oob_data.len=oob_data_len;
    memcpy(gecko_cmd_msg->data.cmd_sm_set_oob_data.oob_data.data,oob_data_data,oob_data_len);
    gecko_cmd_msg->header=((gecko_cmd_sm_set_oob_data_id+((1+oob_data_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_set_oob_data;
}

/** 
*
* gecko_cmd_sm_list_all_bondings
*
* This command can be used to list all bondings stored in the bonding database. Bondings are reported by using the "             sm_list_bonding_entry" event for each bonding and the report is ended with "sm_list_all_bondings_complete" event.              Recommended to be used only for debugging purposes, because reading from the Persistent Store is relatively slow. 
*
*
* Events generated
*
* gecko_evt_sm_list_bonding_entry - 
* gecko_evt_sm_list_all_bondings_complete -     
*
**/

static inline struct gecko_msg_sm_list_all_bondings_rsp_t* gecko_cmd_sm_list_all_bondings()
{
    
    gecko_cmd_msg->header=((gecko_cmd_sm_list_all_bondings_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_list_all_bondings;
}

/** 
*
* gecko_cmd_sm_bonding_confirm
*
* This command can be used for accepting or rejecting bonding request. 
*
* @param connection   Connection handle
* @param confirm   Accept bonding request. Values:
*  - 0: Reject
*  - 1: Accept bonding request
*     
*
**/

static inline struct gecko_msg_sm_bonding_confirm_rsp_t* gecko_cmd_sm_bonding_confirm(uint8 connection,uint8 confirm)
{
    
    gecko_cmd_msg->data.cmd_sm_bonding_confirm.connection=connection;
    gecko_cmd_msg->data.cmd_sm_bonding_confirm.confirm=confirm;
    gecko_cmd_msg->header=((gecko_cmd_sm_bonding_confirm_id+((2)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_bonding_confirm;
}

/** 
*
* gecko_cmd_sm_set_debug_mode
*
* This command can be used to set Security Manager in debug mode. In this mode the secure connections bonding uses debug keys, so that the encrypted packet can be opened by Bluetooth protocol analyzer. To disable the debug mode, you need to restart the device. 
*    
*
**/

static inline struct gecko_msg_sm_set_debug_mode_rsp_t* gecko_cmd_sm_set_debug_mode()
{
    
    gecko_cmd_msg->header=((gecko_cmd_sm_set_debug_mode_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_set_debug_mode;
}

/** 
*
* gecko_cmd_sm_set_passkey
*
* This command can be used to enter a fixed passkey which will be used in the "sm_passkey_display" event. 
*
* @param passkey   Passkey. Valid range: 0-999999. Set -1 to disable and start using random passkeys.    
*
**/

static inline struct gecko_msg_sm_set_passkey_rsp_t* gecko_cmd_sm_set_passkey(int32 passkey)
{
    if(ENDIAN) reverse_endian((uint8*)&passkey,4);

    gecko_cmd_msg->data.cmd_sm_set_passkey.passkey=passkey;
    gecko_cmd_msg->header=((gecko_cmd_sm_set_passkey_id+((4)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_set_passkey;
}

/** 
*
* gecko_cmd_sm_use_sc_oob
*
* This command can be used to enable the use of OOB data (out-of-band encryption data) for a device for secure connections pairing.                 The enabling will genarate new OOB data and confirm values which can be sent to the remote device.                 After enabling the secure connections OOB data, the remote devices OOB data can be set with "sm_set_sc_remote_oob_data".                 Calling this function will erase any set remote device OOB data and confirm values.                 The device will not allow any other kind of bonding if OOB data is set. The secure connections OOB data cannot be enabled simultaneously with legacy pairing OOB data.              
*
* @param enable   Enable OOB with secure connections pairing. Values: 
*  - 0: disable
*  - 1: enable
*     
*
**/

static inline struct gecko_msg_sm_use_sc_oob_rsp_t* gecko_cmd_sm_use_sc_oob(uint8 enable)
{
    
    gecko_cmd_msg->data.cmd_sm_use_sc_oob.enable=enable;
    gecko_cmd_msg->header=((gecko_cmd_sm_use_sc_oob_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_use_sc_oob;
}

/** 
*
* gecko_cmd_sm_set_sc_remote_oob_data
*
* This command can be used to set OOB data and confirm values (out-of-band encryption) received from the remote device for secure connections pairing.                 OOB data must be enabled with "sm_use_sc_oob" before setting the remote device OOB data.              
*
* @param oob_data   Remote device OOB data and confirm values. To set OOB data, send a 32-byte array.                         First 16-bytes is the OOB data and last 16-bytes the confirm value. To clear OOB data, send a zero-length array.    
*
**/

static inline struct gecko_msg_sm_set_sc_remote_oob_data_rsp_t* gecko_cmd_sm_set_sc_remote_oob_data(uint8 oob_data_len, const uint8* oob_data_data)
{

    gecko_cmd_msg->data.cmd_sm_set_sc_remote_oob_data.oob_data.len=oob_data_len;
    memcpy(gecko_cmd_msg->data.cmd_sm_set_sc_remote_oob_data.oob_data.data,oob_data_data,oob_data_len);
    gecko_cmd_msg->header=((gecko_cmd_sm_set_sc_remote_oob_data_id+((1+oob_data_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_set_sc_remote_oob_data;
}

/** 
*
* gecko_cmd_sm_add_to_whitelist
*
* This command can be used to add device to whitelist, which can be enabled with "le_gap_enable_whitelisting"              
*
* @param address   Address of the device added to whitelist
* @param address_type   Address type of the device added to whitelist    
*
**/

static inline struct gecko_msg_sm_add_to_whitelist_rsp_t* gecko_cmd_sm_add_to_whitelist(bd_addr address,uint8 address_type)
{
    
    memcpy(&gecko_cmd_msg->data.cmd_sm_add_to_whitelist.address,&address,sizeof(bd_addr));
    gecko_cmd_msg->data.cmd_sm_add_to_whitelist.address_type=address_type;
    gecko_cmd_msg->header=((gecko_cmd_sm_add_to_whitelist_id+((7)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_sm_add_to_whitelist;
}

/** 
*
* gecko_cmd_homekit_configure
*
* This command can be used to configure the Apple HomeKit accessory and its settings. It is possible to reinitialize configuration in run time. New fast advertising parameters will be used for next fast advertising. 
*
* @param i2c_address   I2C address of Apple authentication coprocessor
* @param support_display   A flag to tell the display support is enabled in the accessory.                                  {br}A pin code will be randomly generated randomly during the pairing process and event "homekit_setupcode_display" event will be produced so the pin code can be shown on the display.                                 
*  - 0: Display support disabled
*  - 1: Display support enabled
* 
* @param hap_attribute_features   The value of Apple HomeKit pairing features supported in pairing service feature characteristic.                  
*  - 0x01: Supports Apple Authentication Coprocessor
*  - 0x02: Supports Software Authentication
*  - 0x00: Only for testing purposes when any authentication method is not available. The accessory will be discovered as non-authenticated
*  - other: Reserved
* 
* @param category   Apple HomeKit accessory category
* @param configuration_number   Apple HomeKit configuration number                                                          {br}By default, this starts from 1. Accessories must increment this value after a firmware update. This value must be managed by the application.
* @param fast_advert_interval   Fast advertising interval. {br}This is used during fast advertising in disconnected state after calling command "homekit_event_notification" when broadcast events advertising is finished.
* @param fast_advert_timeout   Fast advertising timeout. {br}This is used during fast advertising in disconnected state after calling command "homekit_event_notification" when broadcast events advertising is finished.                    
*  - Time = Value x 100 ms
* 
* @param flag   Apple HomeKit library configuration flag.                                 
*  - 0x00000001: Manual Bluetooth disconnection in HomeKit error case. When enabling a "homekit_disconnection_required" event will be produced when appear HomeKit error.
*  - 0x00000002: Manual set of scan response data. When enabling it is possible to use "le_gap_bt5_set_adv_data" command to set custom scan response data. In other case HomeKit library will use it to set accessory local name.                                  - other:  Reserved. Must be 0.
* 
* @param broadcast_advert_timeout   Broadcast events advertising timeout. {br}This is used during broadcast events advertising in disconnected state after calling command "homekit_event_notification"                    
*  - Time = Value x 100 ms
* 
* @param model_name   Model name characteristic value from HomeKit Accessory Information service. Mandatory in case of HomeKit software authentication usage.    
*
**/

static inline struct gecko_msg_homekit_configure_rsp_t* gecko_cmd_homekit_configure(uint8 i2c_address,uint8 support_display,uint8 hap_attribute_features,uint16 category,uint8 configuration_number,uint16 fast_advert_interval,uint16 fast_advert_timeout,uint32 flag,uint16 broadcast_advert_timeout,uint8 model_name_len, const uint8* model_name_data)
{
    if(ENDIAN) reverse_endian((uint8*)&category,2);
    if(ENDIAN) reverse_endian((uint8*)&fast_advert_interval,2);
    if(ENDIAN) reverse_endian((uint8*)&fast_advert_timeout,2);
    if(ENDIAN) reverse_endian((uint8*)&flag,4);
    if(ENDIAN) reverse_endian((uint8*)&broadcast_advert_timeout,2);
    
    gecko_cmd_msg->data.cmd_homekit_configure.i2c_address=i2c_address;
    gecko_cmd_msg->data.cmd_homekit_configure.support_display=support_display;
    gecko_cmd_msg->data.cmd_homekit_configure.hap_attribute_features=hap_attribute_features;
    gecko_cmd_msg->data.cmd_homekit_configure.category=category;
    gecko_cmd_msg->data.cmd_homekit_configure.configuration_number=configuration_number;
    gecko_cmd_msg->data.cmd_homekit_configure.fast_advert_interval=fast_advert_interval;
    gecko_cmd_msg->data.cmd_homekit_configure.fast_advert_timeout=fast_advert_timeout;
    gecko_cmd_msg->data.cmd_homekit_configure.flag=flag;
    gecko_cmd_msg->data.cmd_homekit_configure.broadcast_advert_timeout=broadcast_advert_timeout;
    gecko_cmd_msg->data.cmd_homekit_configure.model_name.len=model_name_len;
    memcpy(gecko_cmd_msg->data.cmd_homekit_configure.model_name.data,model_name_data,model_name_len);
    gecko_cmd_msg->header=((gecko_cmd_homekit_configure_id+((17+model_name_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_homekit_configure;
}

/** 
*
* gecko_cmd_homekit_advertise
*
* This command can be used to start or stop Apple HomeKit accessory advertising. The command and parameters will take effect immediately. If the given parameters can't be used in the currently active mode, an error will be returned. 
*
* @param enable   A flag to enable or disable Apple HomeKit advertising                                 
*  - 1: Enable advertising
*  - 0: Disable advertising
* 
* @param interval_min   Minimum advertising interval. Please refer to GAP command: "le_gap_set_adv_parameters"
* @param interval_max   Maximum advertising interval. Please refer to GAP command: "le_gap_set_adv_parameters"
* @param channel_map   Advertising channel map. Please refer to GAP command: "le_gap_set_adv_parameters"    
*
**/

static inline struct gecko_msg_homekit_advertise_rsp_t* gecko_cmd_homekit_advertise(uint8 enable,uint16 interval_min,uint16 interval_max,uint8 channel_map)
{
    if(ENDIAN) reverse_endian((uint8*)&interval_min,2);
    if(ENDIAN) reverse_endian((uint8*)&interval_max,2);
    
    gecko_cmd_msg->data.cmd_homekit_advertise.enable=enable;
    gecko_cmd_msg->data.cmd_homekit_advertise.interval_min=interval_min;
    gecko_cmd_msg->data.cmd_homekit_advertise.interval_max=interval_max;
    gecko_cmd_msg->data.cmd_homekit_advertise.channel_map=channel_map;
    gecko_cmd_msg->header=((gecko_cmd_homekit_advertise_id+((6)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_homekit_advertise;
}

/** 
*
* gecko_cmd_homekit_delete_pairings
*
* This command can be used to delete all Apple HomeKit pairing data. Additionally it resets all required HomeKit settings to factory state, e.g. it resets GSN value, generates new Device ID. 
*    
*
**/

static inline struct gecko_msg_homekit_delete_pairings_rsp_t* gecko_cmd_homekit_delete_pairings()
{
    
    gecko_cmd_msg->header=((gecko_cmd_homekit_delete_pairings_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_homekit_delete_pairings;
}

/** 
*
* gecko_cmd_homekit_check_authcp
*
* This command can be used to make an I2C test connection with Apple authentication co-processor and return error if communication failed. 
*    
*
**/

static inline struct gecko_msg_homekit_check_authcp_rsp_t* gecko_cmd_homekit_check_authcp()
{
    
    gecko_cmd_msg->header=((gecko_cmd_homekit_check_authcp_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_homekit_check_authcp;
}

/** 
*
* gecko_cmd_homekit_get_pairing_id
*
* This command can be used to get pairing ID of the connected iOS device. 
*
* @param connection       
*
**/

static inline struct gecko_msg_homekit_get_pairing_id_rsp_t* gecko_cmd_homekit_get_pairing_id(uint8 connection)
{
    
    gecko_cmd_msg->data.cmd_homekit_get_pairing_id.connection=connection;
    gecko_cmd_msg->header=((gecko_cmd_homekit_get_pairing_id_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_homekit_get_pairing_id;
}

/** 
*
* gecko_cmd_homekit_send_write_response
*
* This command can be used to send a response to a "homekit_write_request" event. The response needs to be sent within 30 seconds, otherwise no more GATT              transactions are allowed by the remote side.              {br}{br}If the status_code is set to 0 the HAP will send a response informing that the write operation was processed successfully and other values will cause the HAP to send a HAP error status response. 
*
* @param connection   
* @param characteristic   
* @param status_code   HomeKit status code.    
*
**/

static inline struct gecko_msg_homekit_send_write_response_rsp_t* gecko_cmd_homekit_send_write_response(uint8 connection,uint16 characteristic,uint8 status_code)
{
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);
    
    gecko_cmd_msg->data.cmd_homekit_send_write_response.connection=connection;
    gecko_cmd_msg->data.cmd_homekit_send_write_response.characteristic=characteristic;
    gecko_cmd_msg->data.cmd_homekit_send_write_response.status_code=status_code;
    gecko_cmd_msg->header=((gecko_cmd_homekit_send_write_response_id+((4)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_homekit_send_write_response;
}

/** 
*
* gecko_cmd_homekit_send_read_response
*
* This command can be used to send a response to a "homekit_read_request" event. The response needs to be sent within 30 seconds, or otherwise no more GATT transactions are allowed by the remote side.             {br}{br}If status_code is set to 0, the characteristic value is sent to the remote GATT client through HomeKit library in a normal way. Other status_code values will cause a HAP error status response instead of the actual data being sent.             {br}{br}If the value data size is less than attribute_size then the Apple HomeKit library will send new "homekit_read_request" event with suitable offset. The Apple HomeKit library provides automatic formatting for the frame as well encryption. 
*
* @param connection   
* @param characteristic   
* @param status_code   HomeKit Status Code.
* @param attribute_size   Size of attribute value
* @param value   Characteristic value to send to the GATT client through HomeKit library. This is ignored if status_code is not set to 0.    
*
**/

static inline struct gecko_msg_homekit_send_read_response_rsp_t* gecko_cmd_homekit_send_read_response(uint8 connection,uint16 characteristic,uint8 status_code,uint16 attribute_size,uint8 value_len, const uint8* value_data)
{
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);
    if(ENDIAN) reverse_endian((uint8*)&attribute_size,2);
    
    gecko_cmd_msg->data.cmd_homekit_send_read_response.connection=connection;
    gecko_cmd_msg->data.cmd_homekit_send_read_response.characteristic=characteristic;
    gecko_cmd_msg->data.cmd_homekit_send_read_response.status_code=status_code;
    gecko_cmd_msg->data.cmd_homekit_send_read_response.attribute_size=attribute_size;
    gecko_cmd_msg->data.cmd_homekit_send_read_response.value.len=value_len;
    memcpy(gecko_cmd_msg->data.cmd_homekit_send_read_response.value.data,value_data,value_len);
    gecko_cmd_msg->header=((gecko_cmd_homekit_send_read_response_id+((7+value_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_homekit_send_read_response;
}

/** 
*
* gecko_cmd_homekit_gsn_action
*
* This command can be used to make suitable action by HomeKit library for GSN (Global State Number) value. 
*
* @param action   Actions:                  
*  - 0: Reset GSN value to default state
*  - 1: Store GSN value to a PS-key (flash)
*     
*
**/

static inline struct gecko_msg_homekit_gsn_action_rsp_t* gecko_cmd_homekit_gsn_action(uint8 action)
{
    
    gecko_cmd_msg->data.cmd_homekit_gsn_action.action=action;
    gecko_cmd_msg->header=((gecko_cmd_homekit_gsn_action_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_homekit_gsn_action;
}

/** 
*
* gecko_cmd_homekit_event_notification
*
* This command can be used to perform suitable actions for HomeKit notifications according to a connection state and the originator of the change. When device is in connected state and it is local change it sends empty indication to controller. When device is disconnected it starts broadcast events advertising, next after timeout it starts fast advertising. Broadcast and fast advertising parameters are set in "homekit_configure". After fast advertising timeout it reverts previous advertising settings. For both states it sets suitable Global State Number value accoring to HomeKit specification rules.              
*
* @param connection   Connection handle. Ignored for disconnected state.
* @param characteristic   
* @param change_originator   Characteristic value place where change come from:                                 
*  - 0: Remote change (from controller)
*  - 1: Local change (from accessory)
* 
* @param value   Broadcast notify value.    
*
**/

static inline struct gecko_msg_homekit_event_notification_rsp_t* gecko_cmd_homekit_event_notification(uint8 connection,uint16 characteristic,uint8 change_originator,uint8 value_len, const uint8* value_data)
{
    if(ENDIAN) reverse_endian((uint8*)&characteristic,2);

    
    gecko_cmd_msg->data.cmd_homekit_event_notification.connection=connection;
    gecko_cmd_msg->data.cmd_homekit_event_notification.characteristic=characteristic;
    gecko_cmd_msg->data.cmd_homekit_event_notification.change_originator=change_originator;
    gecko_cmd_msg->data.cmd_homekit_event_notification.value.len=value_len;
    memcpy(gecko_cmd_msg->data.cmd_homekit_event_notification.value.data,value_data,value_len);
    gecko_cmd_msg->header=((gecko_cmd_homekit_event_notification_id+((5+value_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_homekit_event_notification;
}

/** 
*
* gecko_cmd_homekit_broadcast_action
*
* This command can be used to make suitable action by HomeKit library for broadcast advertisisng. 
*
* @param action   Actions:                                  
*  - 0x00: Delete broadcast advertising data. No additional parameters are required
*  - 0x01: Store broadcast advertising data (key, charactersitics configuration) to non volatile memory. No additional parameters are required
*  - other: Reserved
* 
* @param params   Additional parameters for action.    
*
**/

static inline struct gecko_msg_homekit_broadcast_action_rsp_t* gecko_cmd_homekit_broadcast_action(uint8 action,uint8 params_len, const uint8* params_data)
{

    
    gecko_cmd_msg->data.cmd_homekit_broadcast_action.action=action;
    gecko_cmd_msg->data.cmd_homekit_broadcast_action.params.len=params_len;
    memcpy(gecko_cmd_msg->data.cmd_homekit_broadcast_action.params.data,params_data,params_len);
    gecko_cmd_msg->header=((gecko_cmd_homekit_broadcast_action_id+((2+params_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_homekit_broadcast_action;
}

/** 
*
* gecko_cmd_coex_set_options
*
* This command is used to configure coexistence options at runtime. 
*
* @param mask   Mask defines which coexistence options are changed.
* @param options   Value of options to be changed. This parameter is used together with mask parameter.    
*
**/

static inline struct gecko_msg_coex_set_options_rsp_t* gecko_cmd_coex_set_options(uint32 mask,uint32 options)
{
    if(ENDIAN) reverse_endian((uint8*)&mask,4);
    if(ENDIAN) reverse_endian((uint8*)&options,4);
    
    gecko_cmd_msg->data.cmd_coex_set_options.mask=mask;
    gecko_cmd_msg->data.cmd_coex_set_options.options=options;
    gecko_cmd_msg->header=((gecko_cmd_coex_set_options_id+((8)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_coex_set_options;
}

/** 
*
* gecko_cmd_coex_get_counters
*
* This command is used to read coexistence statistic counters from the device. Response contains the list of uint32 type counter values. Counters in the list are in following order: low priority requested, high priority requested, low priority denied, high priority denied, low priority tx aborted, high priority tx aborted. 
*
* @param reset   Reset counter values    
*
**/

static inline struct gecko_msg_coex_get_counters_rsp_t* gecko_cmd_coex_get_counters(uint8 reset)
{
    
    gecko_cmd_msg->data.cmd_coex_get_counters.reset=reset;
    gecko_cmd_msg->header=((gecko_cmd_coex_get_counters_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_coex_get_counters;
}

/** 
*
* gecko_cmd_l2cap_coc_send_connection_request
*
* This command is used for sending LE credit based connection request.               
*
* @param connection   Handle of the LE connection to be used for opening connection-oriented channel.
* @param le_psm   LE Protocol/Service Multiplexer - LE_PSM
* @param mtu   The maximum size of payload data that the application on the device
* sending the request is capable of accepting, i.e. the MTU corresponds
* to the maximum SDU size.
* Range:  23 to 65533.
* Application needs to handle segmentation and reassembly from PDU to
* SDU.
* 
* @param mps   The maximum size of payload data that the L2CAP layer on the device
* sending the request is capable of accepting, i.e. the MPS corresponds
* to the maximum PDU payload size.
* Range:  23 to 250.
* That is the maximum size of data that the application is able to send
* using "l2cap_coc_send_data" command or receive by "l2cap_coc_data"
* event.
* 
* @param initial_credit   The initial credit value indicates the number of PDUs that the peer device can send.
*
* Events generated
*
* gecko_evt_l2cap_coc_connection_response - Triggered when a LE credit based connection connection response has been received in response to this command.
* gecko_evt_l2cap_coc_channel_disconnected - Triggered when a LE credit based connection connection response has not been received within the 30 seconds timeout in response to this command.    
*
**/

static inline struct gecko_msg_l2cap_coc_send_connection_request_rsp_t* gecko_cmd_l2cap_coc_send_connection_request(uint8 connection,uint16 le_psm,uint16 mtu,uint16 mps,uint16 initial_credit)
{
    if(ENDIAN) reverse_endian((uint8*)&le_psm,2);
    if(ENDIAN) reverse_endian((uint8*)&mtu,2);
    if(ENDIAN) reverse_endian((uint8*)&mps,2);
    if(ENDIAN) reverse_endian((uint8*)&initial_credit,2);
    
    gecko_cmd_msg->data.cmd_l2cap_coc_send_connection_request.connection=connection;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_connection_request.le_psm=le_psm;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_connection_request.mtu=mtu;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_connection_request.mps=mps;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_connection_request.initial_credit=initial_credit;
    gecko_cmd_msg->header=((gecko_cmd_l2cap_coc_send_connection_request_id+((9)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_l2cap_coc_send_connection_request;
}

/** 
*
* gecko_cmd_l2cap_coc_send_connection_response
*
* This command is used for sending LE credit based connection response.               
*
* @param connection   Handle of the LE connection to be used for opening connection-oriented channel.
* @param cid   The CID represents the destination channel endpoint of the device sending the response which is same as source CID field of corresponding request message.
* @param mtu   The maximum size of payload data that the application on the device
* sending the response is capable of accepting, i.e. the MTU corresponds
* to the maximum SDU size.
* Range:  23 to 65533.
* Application needs to handle segmentation and reassembly from PDU to
* SDU.
* 
* @param mps   The maximum size of payload data that the L2CAP layer on the device
* sending the response is capable of accepting, i.e. the MPS corresponds
* to the maximum PDU payload size.
* Range:  23 to 250.
* That is the maximum size of data that the application is able to send
* using "l2cap_coc_send_data" command or receive by "l2cap_coc_data"
* event.
* 
* @param initial_credit   The initial credit value indicates the number of PDUs that the peer device can send.
* @param result   The result field indicates the outcome of the connection request.    
*
**/

static inline struct gecko_msg_l2cap_coc_send_connection_response_rsp_t* gecko_cmd_l2cap_coc_send_connection_response(uint8 connection,uint16 cid,uint16 mtu,uint16 mps,uint16 initial_credit,uint16 result)
{
    if(ENDIAN) reverse_endian((uint8*)&cid,2);
    if(ENDIAN) reverse_endian((uint8*)&mtu,2);
    if(ENDIAN) reverse_endian((uint8*)&mps,2);
    if(ENDIAN) reverse_endian((uint8*)&initial_credit,2);
    if(ENDIAN) reverse_endian((uint8*)&result,2);
    
    gecko_cmd_msg->data.cmd_l2cap_coc_send_connection_response.connection=connection;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_connection_response.cid=cid;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_connection_response.mtu=mtu;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_connection_response.mps=mps;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_connection_response.initial_credit=initial_credit;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_connection_response.result=result;
    gecko_cmd_msg->header=((gecko_cmd_l2cap_coc_send_connection_response_id+((11)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_l2cap_coc_send_connection_response;
}

/** 
*
* gecko_cmd_l2cap_coc_send_le_flow_control_credit
*
* This command is used for sending LE flow control credit indicating that the channel endpoint on local device is capable of receiving more data.               
*
* @param connection   Handle of the LE connection to be used for sending flow control credit.
* @param cid   The CID represents the destination channel endpoint of the device sending the flow control credit.
* @param credits   The credit value indicates the additional number of PDUs that the peer device can send.    
*
**/

static inline struct gecko_msg_l2cap_coc_send_le_flow_control_credit_rsp_t* gecko_cmd_l2cap_coc_send_le_flow_control_credit(uint8 connection,uint16 cid,uint16 credits)
{
    if(ENDIAN) reverse_endian((uint8*)&cid,2);
    if(ENDIAN) reverse_endian((uint8*)&credits,2);
    
    gecko_cmd_msg->data.cmd_l2cap_coc_send_le_flow_control_credit.connection=connection;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_le_flow_control_credit.cid=cid;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_le_flow_control_credit.credits=credits;
    gecko_cmd_msg->header=((gecko_cmd_l2cap_coc_send_le_flow_control_credit_id+((5)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_l2cap_coc_send_le_flow_control_credit;
}

/** 
*
* gecko_cmd_l2cap_coc_send_disconnection_request
*
* This command is used for sending L2CAP connection-oriented channel disconnection request.              
*
* @param connection   Handle of the LE connection to be used for terminating connection-oriented channel.
* @param cid   The CID represents the destination channel endpoint of the device sending the disconnection request.
*
* Events generated
*
* gecko_evt_l2cap_coc_channel_disconnected - Triggered when a L2CAP channel is disconnected in response to this command.    
*
**/

static inline struct gecko_msg_l2cap_coc_send_disconnection_request_rsp_t* gecko_cmd_l2cap_coc_send_disconnection_request(uint8 connection,uint16 cid)
{
    if(ENDIAN) reverse_endian((uint8*)&cid,2);
    
    gecko_cmd_msg->data.cmd_l2cap_coc_send_disconnection_request.connection=connection;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_disconnection_request.cid=cid;
    gecko_cmd_msg->header=((gecko_cmd_l2cap_coc_send_disconnection_request_id+((3)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_l2cap_coc_send_disconnection_request;
}

/** 
*
* gecko_cmd_l2cap_coc_send_data
*
* This command is used for sending data to a L2CAP LE connection-oriented channel.               
*
* @param connection   Handle of the LE connection to be used for sending data.
* @param cid   The CID represents the destination channel endpoint of the device sending the data.
* @param data   The data to be sent. The data length must be within the range of destination channel endpoint's MPS value.    
*
**/

static inline struct gecko_msg_l2cap_coc_send_data_rsp_t* gecko_cmd_l2cap_coc_send_data(uint8 connection,uint16 cid,uint8 data_len, const uint8* data_data)
{
    if(ENDIAN) reverse_endian((uint8*)&cid,2);

    
    gecko_cmd_msg->data.cmd_l2cap_coc_send_data.connection=connection;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_data.cid=cid;
    gecko_cmd_msg->data.cmd_l2cap_coc_send_data.data.len=data_len;
    memcpy(gecko_cmd_msg->data.cmd_l2cap_coc_send_data.data.data,data_data,data_len);
    gecko_cmd_msg->header=((gecko_cmd_l2cap_coc_send_data_id+((4+data_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_l2cap_coc_send_data;
}

/** 
*
* gecko_cmd_cte_transmitter_enable_cte_response
*
* This command can be used to enable CTE responses on a connection. 
*
* @param connection   Connection handle
* @param cte_types   CTE types. Bitmask of followings,                 
*  - Bit 0: AoA CTE response
*  - Bit 1: AoD CTE response with 1us slots
*  - Bit 2: AoD CTE response with 2us slots
* 
* @param switching_pattern   Antenna switching pattern    
*
**/

static inline struct gecko_msg_cte_transmitter_enable_cte_response_rsp_t* gecko_cmd_cte_transmitter_enable_cte_response(uint8 connection,uint8 cte_types,uint8 switching_pattern_len, const uint8* switching_pattern_data)
{   
    gecko_cmd_msg->data.cmd_cte_transmitter_enable_cte_response.connection=connection;
    gecko_cmd_msg->data.cmd_cte_transmitter_enable_cte_response.cte_types=cte_types;
    gecko_cmd_msg->data.cmd_cte_transmitter_enable_cte_response.switching_pattern.len=switching_pattern_len;
    memcpy(gecko_cmd_msg->data.cmd_cte_transmitter_enable_cte_response.switching_pattern.data,switching_pattern_data,switching_pattern_len);
    gecko_cmd_msg->header=((gecko_cmd_cte_transmitter_enable_cte_response_id+((3+switching_pattern_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_transmitter_enable_cte_response;
}

/** 
*
* gecko_cmd_cte_transmitter_disable_cte_response
*
* This command can be used to disable CTE responses on a connection. 
*
* @param connection   Connection handle    
*
**/

static inline struct gecko_msg_cte_transmitter_disable_cte_response_rsp_t* gecko_cmd_cte_transmitter_disable_cte_response(uint8 connection)
{
    
    gecko_cmd_msg->data.cmd_cte_transmitter_disable_cte_response.connection=connection;
    gecko_cmd_msg->header=((gecko_cmd_cte_transmitter_disable_cte_response_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_transmitter_disable_cte_response;
}

/** 
*
* gecko_cmd_cte_transmitter_start_connectionless_cte
*
* This command can be used to start connectionless CTE transmit. 
*
* @param adv   Periodic advertising handle
* @param cte_length   CTE length in 8 us units
* @param cte_type   Requested CTE type                     
*  - 0: AoA CTE
*  - 1: AoD CTE with 1 us slots
*  - 2: AoD CTE with 2 us slots
* 
* @param cte_count   The number of CTEs to transmit in each periodic advertising interval
* @param switching_pattern   Antenna switching pattern    
*
**/

static inline struct gecko_msg_cte_transmitter_start_connectionless_cte_rsp_t* gecko_cmd_cte_transmitter_start_connectionless_cte(uint8 adv,uint8 cte_length,uint8 cte_type,uint8 cte_count,uint8 switching_pattern_len, const uint8* switching_pattern_data)
{   
    gecko_cmd_msg->data.cmd_cte_transmitter_start_connectionless_cte.adv=adv;
    gecko_cmd_msg->data.cmd_cte_transmitter_start_connectionless_cte.cte_length=cte_length;
    gecko_cmd_msg->data.cmd_cte_transmitter_start_connectionless_cte.cte_type=cte_type;
    gecko_cmd_msg->data.cmd_cte_transmitter_start_connectionless_cte.cte_count=cte_count;
    gecko_cmd_msg->data.cmd_cte_transmitter_start_connectionless_cte.switching_pattern.len=switching_pattern_len;
    memcpy(gecko_cmd_msg->data.cmd_cte_transmitter_start_connectionless_cte.switching_pattern.data,switching_pattern_data,switching_pattern_len);
    gecko_cmd_msg->header=((gecko_cmd_cte_transmitter_start_connectionless_cte_id+((5+switching_pattern_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_transmitter_start_connectionless_cte;
}

/** 
*
* gecko_cmd_cte_transmitter_stop_connectionless_cte
*
* This command can be used to stop connectionless CTE transmit. 
*
* @param adv   Periodic advertising handle    
*
**/

static inline struct gecko_msg_cte_transmitter_stop_connectionless_cte_rsp_t* gecko_cmd_cte_transmitter_stop_connectionless_cte(uint8 adv)
{
    
    gecko_cmd_msg->data.cmd_cte_transmitter_stop_connectionless_cte.adv=adv;
    gecko_cmd_msg->header=((gecko_cmd_cte_transmitter_stop_connectionless_cte_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_transmitter_stop_connectionless_cte;
}

/** 
*
* gecko_cmd_cte_transmitter_set_dtm_parameters
*
* This command can be used to set CTE related parameters of LE transmitter test. 
*
* @param cte_length   Expected length of the Constant Tone Extension in 8 us units
* @param cte_type   CTE type                     
*  - 0: AoA CTE
*  - 1: AoD CTE with 1 us slots
*  - 2: AoD CTE with 2 us slots
* 
* @param switching_pattern   Antenna switching pattern    
*
**/

static inline struct gecko_msg_cte_transmitter_set_dtm_parameters_rsp_t* gecko_cmd_cte_transmitter_set_dtm_parameters(uint8 cte_length,uint8 cte_type,uint8 switching_pattern_len, const uint8* switching_pattern_data)
{
    
    gecko_cmd_msg->data.cmd_cte_transmitter_set_dtm_parameters.cte_length=cte_length;
    gecko_cmd_msg->data.cmd_cte_transmitter_set_dtm_parameters.cte_type=cte_type;
    gecko_cmd_msg->data.cmd_cte_transmitter_set_dtm_parameters.switching_pattern.len=switching_pattern_len;
    memcpy(gecko_cmd_msg->data.cmd_cte_transmitter_set_dtm_parameters.switching_pattern.data,switching_pattern_data,switching_pattern_len);
    gecko_cmd_msg->header=((gecko_cmd_cte_transmitter_set_dtm_parameters_id+((3+switching_pattern_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_transmitter_set_dtm_parameters;
}

/** 
*
* gecko_cmd_cte_transmitter_clear_dtm_parameters
*
* This command can be used to clear CTE related parameters that were previously set for LE transmitter test.  Default values will be restored for these parameters. 
*    
*
**/

static inline struct gecko_msg_cte_transmitter_clear_dtm_parameters_rsp_t* gecko_cmd_cte_transmitter_clear_dtm_parameters()
{
    
    gecko_cmd_msg->header=((gecko_cmd_cte_transmitter_clear_dtm_parameters_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_transmitter_clear_dtm_parameters;
}

/** 
*
* gecko_cmd_cte_receiver_configure
*
* This commmand can be used to configure the CTE sampling mode. 
*
* @param flags   Values: 
*  - 0: Disable raw sample mode
*  - 1: Enable raw sample mode
*     
*
**/

static inline struct gecko_msg_cte_receiver_configure_rsp_t* gecko_cmd_cte_receiver_configure(uint8 flags)
{
    
    gecko_cmd_msg->data.cmd_cte_receiver_configure.flags=flags;
    gecko_cmd_msg->header=((gecko_cmd_cte_receiver_configure_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_receiver_configure;
}

/** 
*
* gecko_cmd_cte_receiver_start_iq_sampling
*
* This command can be used to start IQ samplings on a connection. 
*
* @param connection   Connection handle
* @param interval   Measurement interval                 
*  - 0: No interval. The request is initiated only once.
*  - Other values N: Initiate the request every N-th connection events
* 
* @param cte_length   Minimum length of the CTE being requested in 8 us units
* @param cte_type   Requested CTE type                     
*  - 0: AoA CTE
*  - 1: AoD CTE with 1 us slots
*  - 2: AoD CTE with 2 us slots
* 
* @param slot_durations   Slot durations                     
*  - 1: Switching and sampling slots are 1 us each
*  - 2: Switching and sampling slots are 2 us each
* 
* @param switching_pattern   Antenna switching pattern
*
* Events generated
*
* gecko_evt_cte_receiver_iq_report - Triggered when IQ samples have been received.    
*
**/

static inline struct gecko_msg_cte_receiver_start_iq_sampling_rsp_t* gecko_cmd_cte_receiver_start_iq_sampling(uint8 connection,uint16 interval,uint8 cte_length,uint8 cte_type,uint8 slot_durations,uint8 switching_pattern_len, const uint8* switching_pattern_data)
{
    if(ENDIAN) reverse_endian((uint8*)&interval,2);
    
    gecko_cmd_msg->data.cmd_cte_receiver_start_iq_sampling.connection=connection;
    gecko_cmd_msg->data.cmd_cte_receiver_start_iq_sampling.interval=interval;
    gecko_cmd_msg->data.cmd_cte_receiver_start_iq_sampling.cte_length=cte_length;
    gecko_cmd_msg->data.cmd_cte_receiver_start_iq_sampling.cte_type=cte_type;
    gecko_cmd_msg->data.cmd_cte_receiver_start_iq_sampling.slot_durations=slot_durations;
    gecko_cmd_msg->data.cmd_cte_receiver_start_iq_sampling.switching_pattern.len=switching_pattern_len;
    memcpy(gecko_cmd_msg->data.cmd_cte_receiver_start_iq_sampling.switching_pattern.data,switching_pattern_data,switching_pattern_len);
    gecko_cmd_msg->header=((gecko_cmd_cte_receiver_start_iq_sampling_id+((7+switching_pattern_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_receiver_start_iq_sampling;
}

/** 
*
* gecko_cmd_cte_receiver_stop_iq_sampling
*
* This command can be used to stop the IQ sampling on a connection. 
*
* @param connection   Connection handle    
*
**/

static inline struct gecko_msg_cte_receiver_stop_iq_sampling_rsp_t* gecko_cmd_cte_receiver_stop_iq_sampling(uint8 connection)
{
    
    gecko_cmd_msg->data.cmd_cte_receiver_stop_iq_sampling.connection=connection;
    gecko_cmd_msg->header=((gecko_cmd_cte_receiver_stop_iq_sampling_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_receiver_stop_iq_sampling;
}

/** 
*
* gecko_cmd_cte_receiver_start_connectionless_iq_sampling
*
* This command can be used to start IQ sampling on a periodic advertising synchronization. 
*
* @param sync   Periodic advertising synchronization handle
* @param slot_durations   Slot durations                     
*  - 1: Switching and sampling slots are 1 us each
*  - 2: Switching and sampling slots are 2 us each
* 
* @param cte_count    - 0: Sample and report all available CTEs
*  - Other values: Maximum number of sampled CTEs in each periodic advertising interval
* 
* @param switching_pattern   Antenna switching pattern
*
* Events generated
*
* gecko_evt_cte_receiver_iq_report - Triggered when IQ samples have been received.    
*
**/

static inline struct gecko_msg_cte_receiver_start_connectionless_iq_sampling_rsp_t* gecko_cmd_cte_receiver_start_connectionless_iq_sampling(uint8 sync,uint8 slot_durations,uint8 cte_count,uint8 switching_pattern_len, const uint8* switching_pattern_data)
{
    
    gecko_cmd_msg->data.cmd_cte_receiver_start_connectionless_iq_sampling.sync=sync;
    gecko_cmd_msg->data.cmd_cte_receiver_start_connectionless_iq_sampling.slot_durations=slot_durations;
    gecko_cmd_msg->data.cmd_cte_receiver_start_connectionless_iq_sampling.cte_count=cte_count;
    gecko_cmd_msg->data.cmd_cte_receiver_start_connectionless_iq_sampling.switching_pattern.len=switching_pattern_len;
    memcpy(gecko_cmd_msg->data.cmd_cte_receiver_start_connectionless_iq_sampling.switching_pattern.data,switching_pattern_data,switching_pattern_len);
    gecko_cmd_msg->header=((gecko_cmd_cte_receiver_start_connectionless_iq_sampling_id+((4+switching_pattern_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_receiver_start_connectionless_iq_sampling;
}

/** 
*
* gecko_cmd_cte_receiver_stop_connectionless_iq_sampling
*
* This command can be used to stop IQ sampling on a periodic advertising synchronization. 
*
* @param sync   Periodic advertising synchronization handle    
*
**/

static inline struct gecko_msg_cte_receiver_stop_connectionless_iq_sampling_rsp_t* gecko_cmd_cte_receiver_stop_connectionless_iq_sampling(uint8 sync)
{
    
    gecko_cmd_msg->data.cmd_cte_receiver_stop_connectionless_iq_sampling.sync=sync;
    gecko_cmd_msg->header=((gecko_cmd_cte_receiver_stop_connectionless_iq_sampling_id+((1)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_receiver_stop_connectionless_iq_sampling;
}

/** 
*
* gecko_cmd_cte_receiver_set_dtm_parameters
*
* This command can be used to set CTE related parameters of LE receiver test. 
*
* @param cte_length   Expected length of the Constant Tone Extension in 8 us units
* @param cte_type   Expected CTE type                     
*  - 0: Expect AoA CTE
*  - 1: Expect AoD CTE with 1 us slots
*  - 2: Expect AoD CTE with 2 us slots
* 
* @param slot_durations   Slot durations                     
*  - 1: Switching and sampling slots are 1 us each
*  - 2: Switching and sampling slots are 2 us each
* 
* @param switching_pattern   Antenna switching pattern    
*
**/

static inline struct gecko_msg_cte_receiver_set_dtm_parameters_rsp_t* gecko_cmd_cte_receiver_set_dtm_parameters(uint8 cte_length,uint8 cte_type,uint8 slot_durations,uint8 switching_pattern_len, const uint8* switching_pattern_data)
{
    
    gecko_cmd_msg->data.cmd_cte_receiver_set_dtm_parameters.cte_length=cte_length;
    gecko_cmd_msg->data.cmd_cte_receiver_set_dtm_parameters.cte_type=cte_type;
    gecko_cmd_msg->data.cmd_cte_receiver_set_dtm_parameters.slot_durations=slot_durations;
    gecko_cmd_msg->data.cmd_cte_receiver_set_dtm_parameters.switching_pattern.len=switching_pattern_len;
    memcpy(gecko_cmd_msg->data.cmd_cte_receiver_set_dtm_parameters.switching_pattern.data,switching_pattern_data,switching_pattern_len);
    gecko_cmd_msg->header=((gecko_cmd_cte_receiver_set_dtm_parameters_id+((4+switching_pattern_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_receiver_set_dtm_parameters;
}

/** 
*
* gecko_cmd_cte_receiver_clear_dtm_parameters
*
* This command can be used to clear CTE related parameters that were previously set for LE receiver test. Default values will be restored for these parameters. 
*    
*
**/

static inline struct gecko_msg_cte_receiver_clear_dtm_parameters_rsp_t* gecko_cmd_cte_receiver_clear_dtm_parameters()
{
    
    gecko_cmd_msg->header=((gecko_cmd_cte_receiver_clear_dtm_parameters_id+((0)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_cte_receiver_clear_dtm_parameters;
}

/** 
*
* gecko_cmd_user_message_to_target
*
* This command can be used by an NCP host to send a message to the target application on device. 
*
* @param data   The message    
*
**/

static inline struct gecko_msg_user_message_to_target_rsp_t* gecko_cmd_user_message_to_target(uint8 data_len, const uint8* data_data)
{
    
    gecko_cmd_msg->data.cmd_user_message_to_target.data.len=data_len;
    memcpy(gecko_cmd_msg->data.cmd_user_message_to_target.data.data,data_data,data_len);
    gecko_cmd_msg->header=((gecko_cmd_user_message_to_target_id+((1+data_len)<<8)));
    
    gecko_handle_command(gecko_cmd_msg->header,&gecko_cmd_msg->data.payload);
    
    return NULL;//.rsp_user_message_to_target;
}

#endif
