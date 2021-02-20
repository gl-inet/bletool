/*****************************************************************************
 * @file 
 * @brief Bluetooth stack error codes
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

/**
 * @defgroup SILABS_RETURN_CODE SILABS_RETURN_CODE
 * @ingroup RETURN_CODE
 * RETURN CODE define by silabs
 * @{
 */

#ifndef BG_ERRORCODES
#define BG_ERRORCODES
enum bg_error_spaces
{
	bg_errspc_hardware=1280,
	bg_errspc_bg=256,
	bg_errspc_smp=768,
	bg_errspc_bt=512,
	bg_errspc_application=2560,
	bg_errspc_att=1024,
	bg_errspc_mesh=3072,
	bg_errspc_mesh_foundation=3584,
	bg_errspc_filesystem=2304,
	bg_errspc_l2cap=3328,
	bg_errspc_security=2816,
};
typedef enum bg_error
{
    bg_err_hardware_ps_store_full                                                         =bg_errspc_hardware+1,        ///<Flash reserved for PS store is full
    bg_err_hardware_ps_key_not_found                                                      =bg_errspc_hardware+2,        ///<PS key not found
    bg_err_hardware_i2c_ack_missing                                                       =bg_errspc_hardware+3,        ///<Acknowledge for i2c was not received.
    bg_err_hardware_i2c_timeout                                                           =bg_errspc_hardware+4,        ///<I2C read or write timed out.
    bg_err_success                                                                        =0,                           ///<No error
    bg_err_invalid_conn_handle                                                            =bg_errspc_bg+1,              ///<Invalid GATT connection handle.
    bg_err_waiting_response                                                               =bg_errspc_bg+2,              ///<Waiting response from GATT server to previous procedure.
    bg_err_gatt_connection_timeout                                                        =bg_errspc_bg+3,              ///<GATT connection is closed due procedure timeout.
    bg_err_invalid_param                                                                  =bg_errspc_bg+128,            ///<Command contained invalid parameter
    bg_err_wrong_state                                                                    =bg_errspc_bg+129,            ///<Device is in wrong state to receive command
    bg_err_out_of_memory                                                                  =bg_errspc_bg+130,            ///<Device has run out of memory
    bg_err_not_implemented                                                                =bg_errspc_bg+131,            ///<Feature is not implemented
    bg_err_invalid_command                                                                =bg_errspc_bg+132,            ///<Command was not recognized
    bg_err_timeout                                                                        =bg_errspc_bg+133,            ///<A command or procedure failed or a link lost due to timeout
    bg_err_not_connected                                                                  =bg_errspc_bg+134,            ///<Connection handle passed is to command is not a valid handle
    bg_err_flow                                                                           =bg_errspc_bg+135,            ///<Command would cause either underflow or overflow error
    bg_err_user_attribute                                                                 =bg_errspc_bg+136,            ///<User attribute was accessed through API which is not supported
    bg_err_invalid_license_key                                                            =bg_errspc_bg+137,            ///<No valid license key found
    bg_err_command_too_long                                                               =bg_errspc_bg+138,            ///<Command maximum length exceeded
    bg_err_out_of_bonds                                                                   =bg_errspc_bg+139,            ///<Bonding procedure can't be started because device has no space left for bond.
    bg_err_unspecified                                                                    =bg_errspc_bg+140,            ///<Unspecified error
    bg_err_hardware                                                                       =bg_errspc_bg+141,            ///<Hardware failure
    bg_err_buffers_full                                                                   =bg_errspc_bg+142,            ///<Command not accepted, because internal buffers are full
    bg_err_disconnected                                                                   =bg_errspc_bg+143,            ///<Command or Procedure failed due to disconnection
    bg_err_too_many_requests                                                              =bg_errspc_bg+144,            ///<Too many Simultaneous Requests
    bg_err_not_supported                                                                  =bg_errspc_bg+145,            ///<Feature is not supported in this firmware build
    bg_err_no_bonding                                                                     =bg_errspc_bg+146,            ///<The bonding does not exist.
    bg_err_crypto                                                                         =bg_errspc_bg+147,            ///<Error using crypto functions
    bg_err_data_corrupted                                                                 =bg_errspc_bg+148,            ///<Data was corrupted.
    bg_err_command_incomplete                                                             =bg_errspc_bg+149,            ///<Data received does not form a complete command
    bg_err_not_initialized                                                                =bg_errspc_bg+150,            ///<Feature or subsystem not initialized
    bg_err_invalid_sync_handle                                                            =bg_errspc_bg+151,            ///<Invalid periodic advertising sync handle
    bg_err_smp_passkey_entry_failed                                                       =bg_errspc_smp+1,             ///<The user input of passkey failed, for example, the user cancelled the operation
    bg_err_smp_oob_not_available                                                          =bg_errspc_smp+2,             ///<Out of Band data is not available for authentication
    bg_err_smp_authentication_requirements                                                =bg_errspc_smp+3,             ///<The pairing procedure cannot be performed as authentication requirements cannot be met due to IO capabilities of one or both devices
    bg_err_smp_confirm_value_failed                                                       =bg_errspc_smp+4,             ///<The confirm value does not match the calculated compare value
    bg_err_smp_pairing_not_supported                                                      =bg_errspc_smp+5,             ///<Pairing is not supported by the device
    bg_err_smp_encryption_key_size                                                        =bg_errspc_smp+6,             ///<The resultant encryption key size is insufficient for the security requirements of this device
    bg_err_smp_command_not_supported                                                      =bg_errspc_smp+7,             ///<The SMP command received is not supported on this device
    bg_err_smp_unspecified_reason                                                         =bg_errspc_smp+8,             ///<Pairing failed due to an unspecified reason
    bg_err_smp_repeated_attempts                                                          =bg_errspc_smp+9,             ///<Pairing or authentication procedure is disallowed because too little time has elapsed since last pairing request or security request
    bg_err_smp_invalid_parameters                                                         =bg_errspc_smp+10,            ///<The Invalid Parameters error code indicates: the command length is invalid or a parameter is outside of the specified range.
    bg_err_smp_dhkey_check_failed                                                         =bg_errspc_smp+11,            ///<Indicates to the remote device that the DHKey Check value received doesn't match the one calculated by the local device.
    bg_err_smp_numeric_comparison_failed                                                  =bg_errspc_smp+12,            ///<Indicates that the confirm values in the numeric comparison protocol do not match.
    bg_err_smp_bredr_pairing_in_progress                                                  =bg_errspc_smp+13,            ///<Indicates that the pairing over the LE transport failed due to a Pairing Request sent over the BR/EDR transport in process.
    bg_err_smp_cross_transport_key_derivation_generation_not_allowed                      =bg_errspc_smp+14,            ///<Indicates that the BR/EDR Link Key generated on the BR/EDR transport cannot be used to derive and distribute keys for the LE transport.
    bg_err_bt_error_success                                                               =0,                           ///<Command completed succesfully
    bg_err_bt_unknown_connection_identifier                                               =bg_errspc_bt+2,              ///<Connection does not exist, or connection open request was cancelled.
    bg_err_bt_authentication_failure                                                      =bg_errspc_bt+5,              ///<Pairing or authentication failed due to incorrect results in the pairing or authentication procedure. This could be due to an incorrect PIN or Link Key
    bg_err_bt_pin_or_key_missing                                                          =bg_errspc_bt+6,              ///<Pairing failed because of missing PIN, or authentication failed because of missing Key
    bg_err_bt_memory_capacity_exceeded                                                    =bg_errspc_bt+7,              ///<Controller is out of memory.
    bg_err_bt_connection_timeout                                                          =bg_errspc_bt+8,              ///<Link supervision timeout has expired.
    bg_err_bt_connection_limit_exceeded                                                   =bg_errspc_bt+9,              ///<Controller is at limit of connections it can support.
    bg_err_bt_synchronous_connectiontion_limit_exceeded                                   =bg_errspc_bt+10,             ///<The Synchronous Connection Limit to a Device Exceeded error code indicates that the Controller has reached the limit to the number of synchronous connections that can be achieved to a device. 
    bg_err_bt_acl_connection_already_exists                                               =bg_errspc_bt+11,             ///<The ACL Connection Already Exists error code indicates that an attempt to create a new ACL Connection to a device when there is already a connection to this device.
    bg_err_bt_command_disallowed                                                          =bg_errspc_bt+12,             ///<Command requested cannot be executed because the Controller is in a state where it cannot process this command at this time.
    bg_err_bt_connection_rejected_due_to_limited_resources                                =bg_errspc_bt+13,             ///<The Connection Rejected Due To Limited Resources error code indicates that an incoming connection was rejected due to limited resources.
    bg_err_bt_connection_rejected_due_to_security_reasons                                 =bg_errspc_bt+14,             ///<The Connection Rejected Due To Security Reasons error code indicates that a connection was rejected due to security requirements not being fulfilled, like authentication or pairing.
    bg_err_bt_connection_rejected_due_to_unacceptable_bd_addr                             =bg_errspc_bt+15,             ///<The Connection was rejected because this device does not accept the BD_ADDR. This may be because the device will only accept connections from specific BD_ADDRs.
    bg_err_bt_connection_accept_timeout_exceeded                                          =bg_errspc_bt+16,             ///<The Connection Accept Timeout has been exceeded for this connection attempt.
    bg_err_bt_unsupported_feature_or_parameter_value                                      =bg_errspc_bt+17,             ///<A feature or parameter value in the HCI command is not supported.
    bg_err_bt_invalid_command_parameters                                                  =bg_errspc_bt+18,             ///<Command contained invalid parameters.
    bg_err_bt_remote_user_terminated                                                      =bg_errspc_bt+19,             ///<User on the remote device terminated the connection.
    bg_err_bt_remote_device_terminated_connection_due_to_low_resources                    =bg_errspc_bt+20,             ///<The remote device terminated the connection because of low resources
    bg_err_bt_remote_powering_off                                                         =bg_errspc_bt+21,             ///<Remote Device Terminated Connection due to Power Off
    bg_err_bt_connection_terminated_by_local_host                                         =bg_errspc_bt+22,             ///<Local device terminated the connection.
    bg_err_bt_repeated_attempts                                                           =bg_errspc_bt+23,             ///<The Controller is disallowing an authentication or pairing procedure because too little time has elapsed since the last authentication or pairing attempt failed.
    bg_err_bt_pairing_not_allowed                                                         =bg_errspc_bt+24,             ///<The device does not allow pairing. This can be for example, when a device only allows pairing during a certain time window after some user input allows pairing
    bg_err_bt_unsupported_remote_feature                                                  =bg_errspc_bt+26,             ///<The remote device does not support the feature associated with the issued command.
    bg_err_bt_unspecified_error                                                           =bg_errspc_bt+31,             ///<No other error code specified is appropriate to use.
    bg_err_bt_ll_response_timeout                                                         =bg_errspc_bt+34,             ///<Connection terminated due to link-layer procedure timeout.
    bg_err_bt_ll_procedure_collision                                                      =bg_errspc_bt+35,             ///<LL procedure has collided with the same transaction or procedure that is already in progress.
    bg_err_bt_encryption_mode_not_acceptable                                              =bg_errspc_bt+37,             ///<The requested encryption mode is not acceptable at this time.
 
	bg_err_bt_link_key_cannot_be_changed                                                  =bg_errspc_bt+38,             ///<Link key cannot be changed because a fixed unit key is being used.    bg_err_bt_instant_passed                                                              =bg_errspc_bt+40,             ///<LMP PDU or LL PDU that includes an instant cannot be performed because the instant when this would have occurred has passed.
    bg_err_bt_pairing_with_unit_key_not_supported                                         =bg_errspc_bt+41,             ///<It was not possible to pair as a unit key was requested and it is not supported.
    bg_err_bt_different_transaction_collision                                             =bg_errspc_bt+42,             ///<LMP transaction was started that collides with an ongoing transaction.
    bg_err_bt_channel_assessment_not_supported                                            =bg_errspc_bt+46,             ///<The Controller cannot perform channel assessment because it is not supported.
    bg_err_bt_insufficient_security                                                       =bg_errspc_bt+47,             ///<The HCI command or LMP PDU sent is only possible on an encrypted link.
    bg_err_bt_parameter_out_of_mandatory_range                                            =bg_errspc_bt+48,             ///<A parameter value requested is outside the mandatory range of parameters for the given HCI command or LMP PDU.
    bg_err_bt_simple_pairing_not_supported_by_host                                        =bg_errspc_bt+55,             ///<The IO capabilities request or response was rejected because the sending Host does not support Secure Simple Pairing even though the receiving Link Manager does.
    bg_err_bt_host_busy_pairing                                                           =bg_errspc_bt+56,             ///<The Host is busy with another pairing operation and unable to support the requested pairing. The receiving device should retry pairing again later.
    bg_err_bt_connection_rejected_due_to_no_suitable_channel_found                        =bg_errspc_bt+57,             ///<The Controller could not calculate an appropriate value for the Channel selection operation.
    bg_err_bt_controller_busy                                                             =bg_errspc_bt+58,             ///<Operation was rejected because the controller is busy and unable to process the request.
    bg_err_bt_unacceptable_connection_interval                                            =bg_errspc_bt+59,             ///<Remote device terminated the connection because of an unacceptable connection interval.
    bg_err_bt_advertising_timeout                                                         =bg_errspc_bt+60,             ///<Ddvertising for a fixed duration completed or, for directed advertising, that advertising completed without a connection being created.
    bg_err_bt_connection_terminated_due_to_mic_failure                                    =bg_errspc_bt+61,             ///<Connection was terminated because the Message Integrity Check (MIC) failed on a received packet.
    bg_err_bt_connection_failed_to_be_established                                         =bg_errspc_bt+62,             ///<LL initiated a connection but the connection has failed to be established. Controller did not receive any packets from remote end.
    bg_err_bt_mac_connection_failed                                                       =bg_errspc_bt+63,             ///<The MAC of the 802.11 AMP was requested to connect to a peer, but the connection failed.
    bg_err_bt_coarse_clock_adjustment_rejected_but_will_try_to_adjust_using_clock_dragging=bg_errspc_bt+64,             ///<The master, at this time, is unable to make a coarse adjustment to the piconet clock, using the supplied parameters. Instead the master will attempt to move the clock using clock dragging.
    bg_err_bt_unknown_advertising_identifier                                              =bg_errspc_bt+66,             ///<A command was sent from the Host that should identify an Advertising or Sync handle, but the Advertising or Sync handle does not exist.
    bg_err_bt_limit_reached                                                               =bg_errspc_bt+67,             ///<Number of operations requested has been reached and has indicated the completion of the activity (e.g., advertising or scanning).
    bg_err_bt_operation_cancelled_by_host                                                 =bg_errspc_bt+68,             ///<A request to the Controller issued by the Host and still pending was successfully canceled.
    bg_err_bt_packet_too_long                                                             =bg_errspc_bt+69,             ///<An attempt was made to send or receive a packet that exceeds the maximum allowed packet length.
    bg_err_application_file_open_failed                                                   =bg_errspc_application+1,     ///<File open failed.
    bg_err_application_xml_parse_failed                                                   =bg_errspc_application+2,     ///<XML parsing failed.
    bg_err_application_device_connection_failed                                           =bg_errspc_application+3,     ///<Device connection failed.
    bg_err_application_device_comunication_failed                                         =bg_errspc_application+4,     ///<Device communication failed.
    bg_err_application_authentication_failed                                              =bg_errspc_application+5,     ///<Device authentication failed.
    bg_err_application_incorrect_gatt_database                                            =bg_errspc_application+6,     ///<Device has incorrect GATT database.
	bg_err_application_disconnected_due_to_procedure_collision                            =bg_errspc_application+7,     ///<Device disconnected due to procedure collision.
	bg_err_application_disconnected_due_to_secure_session_failed                          =bg_errspc_application+8,     ///<Device disconnected due to failure to establish or reestablish a secure session.
	bg_err_application_encryption_decryption_error                                        =bg_errspc_application+9,     ///<Encrypion/decryption operation failed.
	bg_err_application_maximum_retries                                                    =bg_errspc_application+10,    ///<Maximum allowed retries exceeded.
	bg_err_application_data_parse_failed                                                  =bg_errspc_application+11,    ///<Data parsing failed.
	bg_err_application_pairing_removed                                                    =bg_errspc_application+12,    ///<Pairing established by the application layer protocol has been removed.
	bg_err_application_inactive_timeout                                                   =bg_errspc_application+13,    ///<Inactive timeout.
	bg_err_application_mismatched_or_insufficient_security                                =bg_errspc_application+14,    ///<Mismatched or insufficient security level
	bg_err_att_invalid_handle                                                             =bg_errspc_att+1,             ///<The attribute handle given was not valid on this server
	bg_err_att_read_not_permitted                                                         =bg_errspc_att+2,             ///<The attribute cannot be read
	bg_err_att_write_not_permitted                                                        =bg_errspc_att+3,             ///<The attribute cannot be written
	bg_err_att_invalid_pdu                                                                =bg_errspc_att+4,             ///<The attribute PDU was invalid
	bg_err_att_insufficient_authentication                                                =bg_errspc_att+5,             ///<The attribute requires authentication before it can be read or written.
	bg_err_att_request_not_supported                                                      =bg_errspc_att+6,             ///<Attribute Server does not support the request received from the client.
	bg_err_att_invalid_offset                                                             =bg_errspc_att+7,             ///<Offset specified was past the end of the attribute
	bg_err_att_insufficient_authorization                                                 =bg_errspc_att+8,             ///<The attribute requires authorization before it can be read or written.
	bg_err_att_prepare_queue_full                                                         =bg_errspc_att+9,             ///<Too many prepare writes have been queueud
	bg_err_att_att_not_found                                                              =bg_errspc_att+10,            ///<No attribute found within the given attribute handle range.
	bg_err_att_att_not_long                                                               =bg_errspc_att+11,            ///<The attribute cannot be read or written using the Read Blob Request
	bg_err_att_insufficient_enc_key_size                                                  =bg_errspc_att+12,            ///<The Encryption Key Size used for encrypting this link is insufficient.
	bg_err_att_invalid_att_length                                                         =bg_errspc_att+13,            ///<The attribute value length is invalid for the operation
	bg_err_att_unlikely_error                                                             =bg_errspc_att+14,            ///<The attribute request that was requested has encountered an error that was unlikely, and therefore could not be completed as requested.
	bg_err_att_insufficient_encryption                                                    =bg_errspc_att+15,            ///<The attribute requires encryption before it can be read or written.
	bg_err_att_unsupported_group_type                                                     =bg_errspc_att+16,            ///<The attribute type is not a supported grouping attribute as defined by a higher layer specification.
	bg_err_att_insufficient_resources                                                     =bg_errspc_att+17,            ///<Insufficient Resources to complete the request
	bg_err_att_out_of_sync                                                                =bg_errspc_att+18,            ///<The server requests the client to rediscover the database.
	bg_err_att_value_not_allowed                                                          =bg_errspc_att+19,            ///<The attribute parameter value was not allowed.
	bg_err_att_application                                                                =bg_errspc_att+128,           ///<When this is returned in a BGAPI response, the application tried to read or write the value of a user attribute from the GATT database.
	bg_err_mesh_already_exists                                                            =bg_errspc_mesh+1,            ///<Returned when trying to add a key or some other unique resource with an ID which already exists
	bg_err_mesh_does_not_exist                                                            =bg_errspc_mesh+2,            ///<Returned when trying to manipulate a key or some other resource with an ID which does not exist
	bg_err_mesh_limit_reached                                                             =bg_errspc_mesh+3,            ///<Returned when an operation cannot be executed because a pre-configured limit for keys, key bindings, elements, models, virtual addresses, provisioned devices, or provisioning sessions is reached
	bg_err_mesh_invalid_address                                                           =bg_errspc_mesh+4,            ///<Returned when trying to use a reserved address or add a "pre-provisioned" device using an address already used by some other device
	bg_err_mesh_malformed_data                                                            =bg_errspc_mesh+5,            ///<In a BGAPI response, the user supplied malformed data; in a BGAPI event, the remote end responded with malformed or unrecognized data
	bg_err_mesh_already_initialized                                                       =bg_errspc_mesh+6,            ///<An attempt was made to initialize a subsystem that was already initialized.
	bg_err_mesh_not_initialized                                                           =bg_errspc_mesh+7,            ///<An attempt was made to use a subsystem that wasn't initialized yet. Call the subsystem's init function first.
	bg_err_mesh_no_friend_offer                                                           =bg_errspc_mesh+8,            ///<Returned when trying to establish a friendship as a Low Power Node, but no acceptable friend offer message was received.
	bg_err_mesh_prov_link_closed                                                          =bg_errspc_mesh+9,            ///<Provisioning link was unexpectedly closed before provisioning was complete.
	bg_err_mesh_prov_invalid_pdu                                                          =bg_errspc_mesh+10,           ///<An unrecognized provisioning PDU was received.
	bg_err_mesh_prov_invalid_pdu_format                                                   =bg_errspc_mesh+11,           ///<A provisioning PDU with wrong length or containing field values that are out of bounds was received.
	bg_err_mesh_prov_unexpected_pdu                                                       =bg_errspc_mesh+12,           ///<An unexpected (out of sequence) provisioning PDU was received.
	bg_err_mesh_prov_confirmation_failed                                                  =bg_errspc_mesh+13,           ///<The computed confirmation value did not match the expected value.
	bg_err_mesh_prov_out_of_resources                                                     =bg_errspc_mesh+14,           ///<Provisioning could not be continued due to unsufficient resources.
	bg_err_mesh_prov_decryption_failed                                                    =bg_errspc_mesh+15,           ///<The provisioning data block could not be decrypted.
	bg_err_mesh_prov_unexpected_error                                                     =bg_errspc_mesh+16,           ///<An unexpected error happened during provisioning.
	bg_err_mesh_prov_cannot_assign_addr                                                   =bg_errspc_mesh+17,           ///<Device could not assign unicast addresses to all of its elements.
	bg_err_mesh_address_temporarily_unavailable                                           =bg_errspc_mesh+18,           ///<Returned when trying to reuse an address of a previously deleted device before an IV Index Update has been executed.
	bg_err_mesh_address_already_used                                                      =bg_errspc_mesh+19,           ///<Returned when trying to assign an address that is used by one of the devices in the Device Database, or by the Provisioner itself.
	bg_err_mesh_foundation_invalid_address                                                =bg_errspc_mesh_foundation+1, ///<Returned when address in request was not valid
	bg_err_mesh_foundation_invalid_model                                                  =bg_errspc_mesh_foundation+2, ///<Returned when model identified is not found for a given element
	bg_err_mesh_foundation_invalid_app_key                                                =bg_errspc_mesh_foundation+3, ///<Returned when the key identified by AppKeyIndex is not stored in the node
	bg_err_mesh_foundation_invalid_net_key                                                =bg_errspc_mesh_foundation+4, ///<Returned when the key identified by NetKeyIndex is not stored in the node
	bg_err_mesh_foundation_insufficient_resources                                         =bg_errspc_mesh_foundation+5, ///<Returned when The node cannot serve the request due to insufficient resources
	bg_err_mesh_foundation_key_index_exists                                               =bg_errspc_mesh_foundation+6, ///<Returned when the key identified is already stored in the node and the new NetKey value is different
	bg_err_mesh_foundation_invalid_publish_params                                         =bg_errspc_mesh_foundation+7, ///<Returned when the model does not support the publish mechanism
	bg_err_mesh_foundation_not_subscribe_model                                            =bg_errspc_mesh_foundation+8, ///<Returned when  the model does not support the subscribe mechanism
	bg_err_mesh_foundation_storage_failure                                                =bg_errspc_mesh_foundation+9, ///<Returned when storing of the requested parameters failed
	bg_err_mesh_foundation_not_supported                                                  =bg_errspc_mesh_foundation+10,//Returned when requested setting is not supported
	bg_err_mesh_foundation_cannot_update                                                  =bg_errspc_mesh_foundation+11,//Returned when the requested update operation cannot be performed due to general constraints
	bg_err_mesh_foundation_cannot_remove                                                  =bg_errspc_mesh_foundation+12,//Returned when the requested delete operation cannot be performed due to general constraints
	bg_err_mesh_foundation_cannot_bind                                                    =bg_errspc_mesh_foundation+13,//Returned when the requested bind operation cannot be performed due to general constraints
	bg_err_mesh_foundation_temporarily_unable                                             =bg_errspc_mesh_foundation+14,//Returned when The node cannot start advertising with Node Identity or Proxy since the maximum number of parallel advertising is reached
	bg_err_mesh_foundation_cannot_set                                                     =bg_errspc_mesh_foundation+15,//Returned when the requested state cannot be set
	bg_err_mesh_foundation_unspecified                                                    =bg_errspc_mesh_foundation+16,//Returned when an unspecified error took place
	bg_err_mesh_foundation_invalid_binding                                                =bg_errspc_mesh_foundation+17,//Returned when the NetKeyIndex and AppKeyIndex combination is not valid for a Config AppKey Update
	bg_err_filesystem_file_not_found                                                      =bg_errspc_filesystem+1,      ///<File not found
	bg_err_l2cap_remote_disconnected                                                      =bg_errspc_l2cap+1,           ///<Returned when remote disconnects the connection-oriented channel by sending disconnection request.
	bg_err_l2cap_local_disconnected                                                       =bg_errspc_l2cap+2,           ///<Returned when local host disconnect the connection-oriented channel by sending disconnection request.
	bg_err_l2cap_cid_not_exist                                                            =bg_errspc_l2cap+3,           ///<Returned when local host did not find a connection-oriented channel with given destination CID.
	bg_err_l2cap_le_disconnected                                                          =bg_errspc_l2cap+4,           ///<Returned when connection-oriented channel disconnected due to LE connection is dropped.
	bg_err_l2cap_flow_control_violated                                                    =bg_errspc_l2cap+5,           ///<Returned when connection-oriented channel disconnected due to remote end send data even without credit.
	bg_err_l2cap_flow_control_credit_overflowed                                           =bg_errspc_l2cap+6,           ///<Returned when connection-oriented channel disconnected due to remote end send flow control credits exceed 65535.
	bg_err_l2cap_no_flow_control_credit                                                   =bg_errspc_l2cap+7,           ///<Returned when connection-oriented channel has run out of flow control credit and local application still trying to send data.
	bg_err_l2cap_connection_request_timeout                                               =bg_errspc_l2cap+8,           ///<Returned when connection-oriented channel has not received connection response message within maximum timeout.
	bg_err_l2cap_invalid_cid                                                              =bg_errspc_l2cap+9,           ///<Returned when local host received a connection-oriented channel connection response with an invalid destination CID.
	bg_err_l2cap_wrong_state                                                              =bg_errspc_l2cap+10,          ///<Returned when local host application tries to send a command which is not suitable for L2CAP channel's current state.
	bg_err_security_image_signature_verification_failed                                   =bg_errspc_security+1,        ///<Device firmware signature verification failed.
	bg_err_security_file_signature_verification_failed                                    =bg_errspc_security+2,        ///<File signature verification failed.
	bg_err_security_image_checksum_error                                                  =bg_errspc_security+3,        ///<Device firmware checksum is not valid.
	bg_err_last
}errorcode_t;


#endif
