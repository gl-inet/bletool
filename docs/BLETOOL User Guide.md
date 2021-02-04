# BLETOOL User Guide



Version：3. 4. 1

Date：2021-02-04

author：Feng.He



**This document is mainly used to introduce the CLI CMD of Bletool. Please refer to the [API documentation](https://dev.gl-inet.com/bletool/group__user) for the C API**



## Description

### What’s bletool？

**BleTool** is a software develop kit for Bluetooth Low Energy (BLE) in GL-iNET’s products. It provides a basic and simple method for developers to operate all the BLE functions. 

Different from BlueZ which includes the full Bluetooth protocol stack in the host system, bletool is a light weight tool to operate hostless BLE modules which has fully built-in protocol stack. The module can fully operate on itself rather than depending on the host system.

To use BleTool, you need to have one of the following devices. 

- GL-S1300 (Convexa-S): Smarthome gateway with beamforming Wi-Fi
- GL-X750 (Spitz): LTE IoT gateway
- GL-XE300 (MEET PULI): Portable 4G LTE WiFi Hotspot with Security Features
- GL-MT300N-V2: (Mini Smart Router): Converting a public network (wired/wireless) to a private Wi-Fi for secure surfing.
- Gl-E750 (MEET MUDI): 4G LTE Privacy Router for Road Warriors
- GL-X300B (MEET COLLIE): 4G LTE Industrial Wireless Gateway
- GL-AP1300 (MEET CIRRUS): Enterprise Ceiling Wireless Access Point
- GL-B2200 (Velica): Whole home mesh system and gateway

You can also use BleTool if you use Silconlabs EFR32 BLE modules which use UART/SPI to connect to your host Linux.

### How to install

By default, BleTool is not installed on your router. You can install it using opkg if you can ssh to the router.

```shell
opkg update

opkg install gl-bletool
```

Alternatively, you can install using the web UI. Login your router’s web UI using your browser which is http://192.168.8.1 by default. Then go to APPLICATIONS->Plug-ins. First click “Update” to refresh your software repo then search “gl-bletool”. Click “install” and wait until you got “installation successfully”.

### How to use

BleTool provides the following elements to handle BLE advertising, connection and GATT services.

- C/C++ APIs: This includes C functions, C header files based on which you can write your own code.
- C/C++ library: You can link this library with your own C application. You need to include the C header files in your own code to compile. 
- cli (command line) tools: cli is commands that you can run in Linux terminal. You can use cli tools to test your BLE applications quickly and easily.



## CLI Command Instruction

### enable

```shell
bletool enable 1
```

**Description**：Enable or disable the BLE hardware.

**Parameters**：

| Type    | Name   | Default Value* | Description                                                  |
| ------- | ------ | -------------- | ------------------------------------------------------------ |
| int32_t | enable | 1              | 0 means disable the BLE hardware;  None-zero means enable the BLE hardware. |

***A default value means you may not set this parameter. “-” means you must set this parameter.***

### local_address

```shell
bletool local_address
```

**Description**：Get the Local Bluetooth MAC address.

### set_power

```
bletool set_power 80
```

**Description**：Set the global power level.

**Parameters**：

| Type    | Name  | Default Value | Description                    |
| ------- | ----- | ------------- | ------------------------------ |
| int32_t | power | -             | Power level  （0.1 dBm steps） |

### listen

```
bletool listen
```

**Description**：This command will not return. It will continuously print events generated from BLE module.

### adv_data

```
bletool adv_data –f 0 –v 020106
```

**Description**：Act as BLE slave, set customized advertising data

**Parameters**:

| Type    | Name           | Default Value | Description                  |
| ------- | -------------- | ------------- | ---------------------------- |
| int32_t | flag    **-f** | -             | Adv data flag.               |
| string  | data  **-v**   | -             | Customized advertising data. |

### adv

```
bletool adv
```

**Description**：Set the advertising parameters and start advertising act as BLE slave.

**Parameters**:

| Type    | Name                       | Default Value | Description                                                  |
| ------- | -------------------------- | ------------- | ------------------------------------------------------------ |
| int32_t | phys                **-p** | 1             | The PHY on which the advertising packets are  transmitted on. |
| int32_t | interval_min   **-n**      | 160  (100ms)  | Minimum advertising interval.                                |
| int32_t | interval_max  **-x**       | 160  (100ms)  | Maximum advertising interval.                                |
| int32_t | discover          **-d**   | 2             | Discoverable mode.                                           |
| int32_t | connect           **-c**   | 2             | Connectable mode.                                            |

### adv_stop

```
bletool adv_stop 
```

**Description**：Act as BLE slave, Stop advertising.

### send_notify

```
bletool send_notify -a 11:22:33:44:55:66 -h 19 -v 0123
```

**Description**：Act as BLE slave, send Notification to remote device.

**Parameters**:

| Type    | Name                        | Default Value | Description                                                  |
| ------- | --------------------------- | ------------- | ------------------------------------------------------------ |
| int32_t | address           **-a**    |               | The MAC address of the remote device                         |
| int32_t | char_handle   **-h**        |               | GATT characteristic handle                                   |
| int32_t | value                **-v** |               | Data value to be sent.(Must be hexadecimal ASCII. Like “020106”) |

### discovery

```
bletool discovery
```

**Description**：Act as master, set and start the BLE discovery.

Note that you have to using command “bletool listen*”* to receive BLE advertising packets after this command.

**Parameters**:

| Type    | Name                | Default Value | Description               |
| ------- | ------------------- | ------------- | ------------------------- |
| int32_t | phys       **-p**   | 1             | The scanning PHY.         |
| int32_t | interval   **-i**   | 16  (10ms)    | Scan interval.            |
| int32_t | window  **-w**      | 16  (10ms)    | Scan window.              |
| int32_t | type         **-t** | 0             | Scan type.                |
| int32_t | mode      **-m**    | 1             | Bluetooth discovery Mode. |

### stop_discovery

```
bletool stop_discovery
```

**Description**：Act as master, stop discovery procedure.

### connect

```
bletool connect –a 11:22:33:44:55:66 –t 0
```

**Description**：Act as master, start connect to a remote BLE device.

**Parameters:**

| Type    | Name                         | Default Value | Description                |
| ------- | ---------------------------- | ------------- | -------------------------- |
| string  | address           **-a**     | -             | Remote BLE device address. |
| int32_t | address_type  **-t**         | -             | Advertiser address type.   |
| int32_t | phy                   **-p** | 1             | The initiating PHY.        |

### disconnect

```
bletool disconnect -a 11:22:33:44:55:66
```

**Description**：Act as master, disconnect with remote device.

**Parameters**:

| Type   | Name             | Default Value | Description                           |
| ------ | ---------------- | ------------- | ------------------------------------- |
| string | address   **-a** | -             | The  MAC address of the remote device |

### get_rssi

```
bletool get_rssi –a 11:22:33:44:55:66
```

**Description**：Act as master, get rssi of connection with remote device.

**Parameters**:

| Type   | Name             | Default Value | Description                           |
| ------ | ---------------- | ------------- | ------------------------------------- |
| string | address   **-a** | -             | The  MAC address of the remote device |

### get_service

```
bletool get_service –a 11:22:33:44:55:66
```

**Description**：Act as master, get service list of a remote GATT server.

**Parameters**:

| Type   | Name             | Default Value | Description                           |
| ------ | ---------------- | ------------- | ------------------------------------- |
| string | address   **-a** | -             | The  MAC address of the remote device |

### get_char

```
bletool get_char –a 11:22:33:44:55:66 –h 10789 
```

**Description**：Act as master, Get characteristic list of a remote GATT server.

**Parameters**:

| Type    | Name                        | Default Value | Description                          |
| ------- | --------------------------- | ------------- | ------------------------------------ |
| string  | address              **-a** | -             | The MAC address of the remote device |
| int32_t | service_handle  **-h**      | -             | Service handle                       |

### set_notify

```
bletool set_notify –a 11:22:33:44:55:66 –h 10789 –f 1
```

**Description**：Act as master, Enable or disable the notification or indication of a remote gatt server.

**Parameters**:

| Type    | Name                         | Default Value | Description                          |
| ------- | ---------------------------- | ------------- | ------------------------------------ |
| string  | address          **-a**      | -             | The MAC address of the remote device |
| int32_t | char_handle  **-h**          | -             | Characteristic handle                |
| int32_t | flag                  **-f** | -             | Notification flag.                   |

### read_value

```
bletool read_value –a 11:22:33:44:55:66 –h 10789
```

**Description**：Act as master, Read value of specified characteristic in a remote gatt server.

**Parameters**:

| Type    | Name                     | Default Value | Description                          |
| ------- | ------------------------ | ------------- | ------------------------------------ |
| string  | address           **-a** | -             | The MAC address of the remote device |
| int32_t | char_handle   **-h**     | -             | Characteristic handle                |

### write_value

```
bletool write_value –a 11:22:33:44:55:66 –h 10789 –v 00000000 –r 0
```

**Description**：Act as master, Write value to specified characteristic in a remote gatt server.

**Parameters**:

| Type    | Name                         | Default Value | Description                          |
| ------- | ---------------------------- | ------------- | ------------------------------------ |
| string  | address          **-a**      | -             | The MAC address of the remote device |
| int32_t | char_handle  **-h**          | -             | Characteristic handle                |
| string  | value               **-v**   |               | Value to be written                  |
| int32_t | res                   **-r** | 0             | Response flag                        |



## Error Code

When some error occurs while executing the relevant API. These error codes can be used to find the cause of the error.

Note: There are two sets of error codes, one is GL error code, the other is the ble module manufacturer(Silabs) error code.

### [GL error code](https://dev.gl-inet.com/bletool/group__gl-return-code)

### [Silabs error code](https://dev.gl-inet.com/bletool/group__silabs-return-code)



