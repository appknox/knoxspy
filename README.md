# KnoxSpy

The KnoxSpy is an open source penetration testing tool developed by **Appknox**, to fill the gap in effective tools effective tools for intercepting and analyzing MDM traffic through dynamic instrumentation with Frida. It integrates with the network libraries of the target application to capture traffic prior to its entry into the MDM tunnel and subsequent to its exit, allowing for real-time inspection and modification of API calls. KnoxSpy streamlines the visualization and monitoring of network traffic. It accommodating not only MDM applications but also a range of other Android and iOS applications.

![](./screenshots/android.gif)

## Installation

- You can download knoxyspy by cloning the Git repository
    ```plain
    git clone https://github.com/appknox/knoxspy.git
    ```
- Install dependencies
    ```bash
    cd app/gui && npm i
    cd ../server && npm i
    ```

## Usage

1. Install Frida server on your device and connect the device to your computer via USB.
2. Launch KnoxSpy
    ```plain
    ./knoxspy
    ```
3. Navigate to the MDM dashboard
    ```plain
    http://localhost:5173/
    ```
4. Click "Create new Session" button.
5. Select the newly created session to open it.
6. Click on the application to spawn it.
7. Choose the network library script from available options.
8. Navigate to the "Proxy" tab in the dashboard to monitor the API calls.

## Features

1. **Intuitive Dashboard Interface**
    - Modern, user-friendly design
    - Easy-to-navigate controls
    - Real-time traffic monitoring

2. **Extensive Network Library Support**
    - iOS
        - Alamofire
        - TrustKit
        - AFNetworking
    - Android
        - OkHttp3

3. **Extensible Architecture**
    - Custom network library integration

4. **Wide Application Coverage**
    - Compatible with MDM applications
    - Works with general Android/iOS apps

5. **Multi-Session Management**

> [!NOTE]
> You can provide your own script and use it instead of bundled scripts.

## License

This project is licensed under Apache-License 2.0.