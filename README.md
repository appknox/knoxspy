# KnoxSpy

<img alt="image" src="https://github.com/ajay-appknox/mdm_dashboard/assets/98275091/a6c05942-be1c-4b3b-bb68-373a9a6faf57">


### Installation
1. Clone the repo:
    ```bash
    git clone https://github.com/appknox/knoxspy.git
    ```
2. Install dependencies:
    ```bash
    cd knoxspy/app/gui && npm i
    cd ../server && npm i && cd ../..
    ```
### Usage

1. Install and start frida server on the device & connect it.
2. Run `./knoxspy` shell script to start server & client.
3. Open http://localhost:5173 to access the app.
4. Create a new session and open it.
