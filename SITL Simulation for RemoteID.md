# SITL Simulation for Remote ID testing
This guide outlines the steps necessary to use Ardupilot's SITL(software in the loop) simulation capabilities in order to test the TBRD proof of concept implementation or other physical Remote ID modules, such as an ESP32-s3-dev.  Use of this simulations should be strictly limited to testing developmental firmware.  Broadcasting simulated drone activity may be restricted by varying local laws and regulations.

## System Requirements
This guide assumes the following system requirements have been met:

### Hardware

- At least one of the ARduPilot Remote ID supported boards listed [here](https://github.com/ArduPilot/ArduRemoteID)
- USB or DroneCAN connection to your Remote ID board
- Some means of verifying Remote ID broadcasts:
  - External Wifi adapter
  - External Bluetooth sniffer
  - Mobile Device running iOS or Android
 
### Software

- Linux development environment (something like Ubuntu 22.04)
- Ardupilot (https://ardupilot.org/dev/docs/sitl-simulator-software-in-the-loop.html) 
- ArduRemoteID firmware properly flashed to your Remote ID module (https://github.com/ArduPilot/ArduRemoteID)
- For verifying RemoteID broadcasts:
  - If using a WiFi or Bluetooth adapater to capture broadcasts, Wireshark 4.2.9 with custom Remote ID disector (https://github.com/opendroneid/wireshark-dissector)
  - If using a mobile device, Drone Scanner App (https://github.com/dronetag/drone-scanner) note - iOS only able to capture bluetooth RemoteID broadcasts

## Simulation Setup

### Setting up Ardupilot
Once you have completed sets to build the Ardupilot environment outlined [here](https://ardupilot.org/dev/docs/building-setup-linux.html#building-setup-linux), build the code for your SITL autopilot by running the following commands:

```
./waf configure --board sitl --enable-opendroneid
./waf copter
```

In the /ArduCopter directory, create a `remoteid.scr` file with the following content:

```
module load OpenDroneID

opendroneid set UAS_ID_type 1
opendroneid set UA_type 1
opendroneid set area_ceiling 700  #only needed if testing swarms
opendroneid set area_count 1      #only needed if testing swarms
opendroneid set area_floor -200   #only needed if testing swarms
opendroneid set area_radius 1000  #only needed if testing swarms
opendroneid set category_eu 1
opendroneid set class_eu 1
opendroneid set classification_type 1
opendroneid set description "TestDrone1"
opendroneid set description_type 1
opendroneid set operator_id "TestPilot1"
opendroneid set operator_id_type 1
opendroneid set operator_location_type 0      #note that a value of 1 is usually required in actual operation. This requires using a GCS with its own GPS for testing.
opendroneid set rate_hz 1
```

### Simulation set-up
Connect your RemoteID module to your computer that will be running the Arudpiolot SITL simulation via USB or DroneCan interface.  For linux users, ensure the user profile is a member of the dialout group by running the following command (logout/resart is required after running the command):

`sudo usermod -a -G dialout $USER`

Now run the following command from the /ardupilot/ArduCopter directory, where `<path>` is the path to your RemoteID module e.g. `/dev/ttyUSB0`

`sim_vehicle.py --console --map -A "--serial1=uart:<path>" --waf-configure-arg=--enable-opendroneid`

Alternatively, if you are testing with the TBRD system use the following command to output the flight data to a udp client.

`sim_vehicle.py --console --map -A "--serial1=udpclient:127.0.0.1:14555" --waf-configure-arg=--enable-opendroneid`

Four windows should now be open.

1. MavProxy Command Prompt
2. ArduCopter
3. Map
4. Console

![Ardupilot SITL Simulation](/docs/ArduPilotSimulation.png)

In the MavProxy Command Prompt run the following command to load the OpenDroneID module and set opendroneid parameters

`script remoteid.scr`

Set the following paramaters using the MavProxy command prompt:

`param set DID_ENABLE 1`

**Note**
You may need to restart your simulation in order to access the following parameters, but ensure to run the remoteid script everytime you restart the simulator

```
param set DID_OPTIONS 0
param set DID_MAVPORT 1
param set DID_CANDRIVER 0
param set AHRS_EKF_TYPE 3
param set GPS1_TYPE 1
param set GPS2_TYPE 0
```
If you are connecting to your Remote ID module using DroneCAN, use the following parameters instead

```
param set DID_MAVPORT -1
param set DID_CANDRIVER 1
```

Once all parameters have been set properly, there should no longer be any red or yellow highlighted warnings in the Console.  You should not be ready to fly your simulated drone.

### Flying your simulated drone
In the MavProxy Command Prompt, use the following commands to arm and takeoff.

```
mode guided
arm throttle
takeoff 40
```
See (https://ardupilot.org/dev/docs/copter-sitl-mavproxy-tutorial.html) for more information on how to interact with your simulated drone.

## Verifying Remote ID Broadcast
Many options exist to verify the RemoteID broadcast. Here are some options:

### TBRD receiver
You can use the TBRD receiver application to receive TBRD authenticated messages.

### Ubertooth and Wireshark
First ensure you are able to capture bluetooth traffic by following the procedures [here](https://ubertooth.readthedocs.io/en/latest/capturing_BLE_Wireshark.html)
Next, use the custom wireshark dissector provided [here](https://github.com/opendroneid/wireshark-dissector) to view the capture. (Note - Wireshark 4.2.9 is required to use the dissector)

