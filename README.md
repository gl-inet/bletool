# bletool

**Note: This project has been replaced by https://github.com/gl-inet/gl-ble-sdk**

BleTool is a software develop kit for Bluetooth Low Energy (BLE) in GL-iNET’s products. It provides a basic and simple method for developers to operate all the BLE functions. 
Different from BlueZ which includes the full Bluetooth protocol stack in the host system, bletool is a light weight tool to operate hostless BLE modules which has fully built-in protocol stack. The module can fully operate on itself rather than depending on the host system.
To use BleTool, you need to have one of the following devices.

- GL-S1300 (Convexa-S): Build-in BLE
- GL-X750 (Spitz): Please choose BLE version
- GL-XE300 (MEET PULI): Pls choose BLE version
- GL-MT300N-V2: (Mini Smart Router): The router does come with BLE. Only customized version with BLE is supported.
- Gl-E750 (MEET MUDI): Pls choose BLE version
- GL-X300B (MEET COLLIE): Pls choose IoT (BLE) version
- GL-AP1300 (MEET CIRRUS): Pls choose BLE version
- GL-B2200 (Velica): Build-in BLE

You can also use BleTool if you use Silconlabs EFR32 BLE modules which use UART/SPI to connect to your host Linux.

## how to install

By default, BleTool is not installed on your router. You can install it using opkg if you can ssh to the router.

```
opkg update
opkg install gl-bletool
```
Alternatively, you can install using the web UI. Login your router’s web UI using your browser which is http://192.168.8.1 by default. Then go to APPLICATIONS->Plug-ins. First click “Update” to refresh your software repo then search “gl-bletool”. Click “install” and wait until you got “installation successfully”.

![installipk](docs/installipk.png)
![installsuccessful](docs/installsuccessful.png)

## how to use

BleTool provides the following elements to handle BLE advertising, connection and GATT services.

- C/C++ APIs: This includes C functions, C header files based on which you can write your own code.
- C/C++ library: You can link this library with your own C application. You need to include the C header files in your own code to compile. 
- cli (command line) tools: cli is commands that you can run in Linux terminal. You can use cli tools to test your BLE applications quickly and easily.
Here is example of how to use cli commands.

![openwrt](docs/openwrt.png)

## API Reference

Look at the [Bletool manual](https://dev.gl-inet.com/bletool/group__user). It contains all detail about the API and CLI.

## Directory Structure

```cpp
|—— LICENSE
|
|—— Makefile
|
|—— VERSION_FILE
|
|—— README.md
|
|—— docs								        # document
|
|—— files
|	|—— gl_bletool.init					        # configuration file
|
|—— src
    | 	|—— components
    |   |   |—— dev_mgr
    |	    |—— log
    |
    |—— daemon 							        # ble daemon
    |   |—— gl_daemon.c
    |   |—— bledriver
    |       |——silabs					        # silabs SDK
    |       |——util 					        # utilities   
    |
    |—— include                    		        # header file
        |—— gl_errno.h
    |   |—— gl_type.h
    |
    |—— lib                        		        # ble api lib
    |   |—— gl_bleapi.h
    |   |—— gl_bleapi.c
    |
    |—— project                			        # user application file
    |   |—— gl_demo.c	     				    # demo file
    |
    |—— tool                     	
    |   |—— gl_cli.c						    # debug tool – bletool
    |
    |—— Makefile
```
