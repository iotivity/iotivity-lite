IoTivity-Lite Android port
-------------------------------------------------

Getting Started
=================================================
To use this code you will need the following:
  - git version control system
  - IoTivity-lite
  - SWIG
  - Java Development kit.
  - Android SDK
  - Android NDK
  - Gradle build system

The following contains instructions to obtain and run the tools on Linux.

### Get Tools
It can be installed on Ubuntu Linux using the following command.

    sudo apt-get install git make openjdk-8-jdk swig

### Get IoTivity-Lite
Checkout IoTivity-lite git project run the following command to get a anonymous copy of
iotivity-lite.  Checkout the SWIG branch.

    git clone https://gerrit.iotivity.org/gerrit/iotivity-lite
    git checkout -t origin/swig

### Android SDK tools
Download the [Android SDK command line tools](https://developer.android.com/studio#downloads)
run `sdkmanager` found in the `tools/bin` directory to install the platform-tools and Android platform

    ./sdkmanager "platform-tools" "platforms;android-23"

if behind a proxy use the proxy connection options

    ./sdkmanager --proxy=<http|socks> --proxy_host=<host address> --proxy_port=<number> "platform-tools" "platforms;android-23"

### Android NDK
Download Android NDK

https://developer.android.com/ndk/downloads/index.html

Unzip downloaded package.

    cd <NDK>/build/tools
    sudo apt-get install python
    ./make_standalone_toolchain.py --arch <architecture> --api <level> --install-dir <path>

valid values for `--arch`
 - arm
 - arm64
 - x86
 - x86_64

The `make_standalone_toolchain` script only supports api level 16 and newer. We recommend using api
level 23 or newer.

For example:

    ./make_standalone_toolchain.py --arch arm --api 23 --install-dir ~/android-arm-23

Note: running the `make_standalone_toolchain.py` script may print a WARNING stating it is no longer
necessary.  This is expected.  At this time the make files expect the stand alone tool chain.

For further setup see:

https://developer.android.com/ndk/guides/standalone_toolchain.html

### Android Studio (optional)
Developers wishing to use Android Studio can find details here:

[Android Studio](https://developer.android.com/studio)

Building IoTivity-Lite libraries
=================================================
To build for Android cd to

    cd <iotivity-lite>/android/port

The Makefile uses then the Android NDK that was installed above.

Either set ANDROID_API and ANDROID_BASE in the Makefile or invoke like this:

    make NDK_HOME=/opt/android-ndk ANDROID_API=23

Example Usage:

    make IPV4=1 DEBUG=1

or

    make NDK_HOME=~/android-arm-23 ANDROID_API=23 IPV4=1 DEBUG=1

The Make file will build and copy the library files (*.so and *.jar) into the
provided samples.

If developing your own project you may need to manually copy the libraries from
`<iotivity-lite-root>/swig/iotivity-lite-java/libs` to the location expected
by your project.

Building and Running Samples
=================================================
All samples have the default out of the box behavior of IoTivity-Lite which means they are are not
onboarded or provisioned.  The default security will prevent the samples from communicating with
one another till onboarding and provisioning has been completed.  See the following section
**Onboarding and Provisioning** for instructions on using the onboarding tool that is part of
iotivity-lite.

A sample server and client can be found in `<iotivity-lite>/swig/apps/<sample>`

Note that gradlew will require a `local.properties` to exist or ANDROID_HOME to be defined.  An
installation of Android Studio should create the `local.properties` file.

example:

    export ANDROID_HOME=~/Android/sdk


To resolve any proxy issues reference [gradle user guide for proxy](https://docs.gradle.org/current/userguide/build_environment.html#sec:accessing_the_web_via_a_proxy)

The server sample is in `android_simple_server/SimpleServer`.  To build and install the sample
execute the following command:

### Method 1
    ./gradlew installDebug

### Method 2
    ./gradlew assembleDebug

To install

    cd app/build/outputs/apk
    adb install app-armeabi-debug.apk

The client sample is in `android_simple_client/SimpleClient`.  To build and install the sample
execute the following command:

### Method 1
    ./gradlew installDebug

### Method 2
    ./gradlew assembleDebug

To install

    cd app/build/outputs/apk
    adb install app-armeabi-debug.apk

Onboarding and Provisioning
=================================================
### Runing the onboarding tool

At this time there are two versions of the onboarding tool.  The C version and the Java version.
The versions are identical. The exception being that the C version is currently built only for
Linux. While the Java version is available for both windows and Linux.  It does not matter which
version of the onboarding tool.

The C version of the onboarding tool can be found in `<iotivity-lite>/port/linux` see Linux build
instructions.

A Java version of the onboarding-tool that will run on Windows or Linux can be found

A sample server and client can be found in `<iotivity-lite>/swig/apps/java_onboarding_tool`

Assuming you have already followed the `Building for Linux` or `Building for Windows` build
instructions the following commands can be used to build and run the onboarding tool.

Linux:

    build-onboarding-tool-lite.sh
    run-onboarding-tool-lite.sh

Windows

    sh build-onboarding-tool-lite.sh
    run-onboarding-tool-lite.cmd

### Simple Step-by-Step guide for onboarding and provisioning

This guide assumes you are starting one discoverable device at a time. Multiple devices can be
discovered and onboarded at the same time however it becomes the responsibility of the user to
figure out which UUID belongs to which device.

Once you have successfully onboarded the samples the first time using the following step-by-step
options feel free to RESET the devices and play around with different provisioning options.

### (Step 1) Onboard and Provision the Server

 - start the server sample
 - start onboarding tool it will print the following menu:

```
    ################################################
    OCF 1.3 Onboarding Tool
    ################################################
    [0] Display this menu
    -----------------------------------------------
    [1] Discover un-owned devices
    [2] Discover owned devices
    -----------------------------------------------
    [3] Take ownership of device (Just-works)
    [4] Provision pair-wise credentials
    [5] Provision ACE2
    -----------------------------------------------
    [6] RESET device
    -----------------------------------------------
    [9] Exit
    ################################################
    
    Select option:
```

 - Type `1` **Enter** to _Discover un-owned devices_ this should display a something similar to
   this

    Discovered unowned device: c3e5c231-9f95-4859-6d11-87f40b1977d5 at:
    [fe80:0000:0000:0000:05a8:81bd:23cf:3882]:59584
    [fe80:0000:0000:0000:05a8:81bd:23cf:3882]:59585

 - Type `3` **Enter** to _Take ownership of device_
   - Type `0` **Enter**. If you have multiple unowned devices you will have to select the correct
     device from the list.  The following should be displayed

    Successfully issued request to perform ownership transfer

 - Type `2` **Enter** to _Discover owned devices_ the device you just took ownership of should be
   listed.
 - Type `5` **Enter** to _Provision ACE2_. There are many ways to properly provision the device.
   This will give instruction for using wildcard provisioning.
   - Type `0` **Enter**. If you have multiple unowned devices you will have to select the correct
     device from the list.
   - Type `1` **Enter** for an _auth-crypt_ ACE
   - Type `1` **Enter** in response to `Enter number of resources in this ACE:`
   - Type `0` **Enter** in response to `Have resource href? [0-No, 1-Yes]:`
   - Type `1` **Enter** in response to `Set wildcard resource? [0-No, 1-Yes]:`
   - Type `2` **Enter** to select the `[2]: All discoverable resources` option
   - Type `0` **Enter** in response to `Enter number of resource types [0-None]:`
   - Type `0` **Enter** in response to `Enter number of interfaces [0-None]`
   - Type `0` **Enter** for CREATE, `1` **Enter** for RETRIEVE, `1` **Enter** for UPDATE, `0`
     **Enter** for DELETE, and `1` **Enter** for NOTIFY.
   - `Successfully issued request to provision ACE` should be printed on the screen upon success

Example output from following the above listed commands:

    Provision ACL2
    My Devices:
    [0]: 33cd6782-00f3-49db-624e-fda26e945c8d


    Select device for provisioning: 0

    Subjects:
    [0]: anon-clear
    [1]: auth-crypt
    [2]: 33cd6782-00f3-49db-624e-fda26e945c8d

    Select subject: 1

    Enter number of resources in this ACE: 1

    Resource properties
    Have resource href? [0-No, 1-Yes]: 0

    Set wildcard resource? [0-No, 1-Yes]: 1
    [1]: All resources
    [2]: All discoverable resources
    [3]: All non-discoverable resources

    Select wildcard resource: 2
    Enter number of resource types [0-None]: 0
    Enter number of interfaces [0-None]0

    Set ACE2 permissions
    CREATE [0-No, 1-Yes]: 0
    RETRIEVE [0-No, 1-Yes]: 1
    UPDATE [0-No, 1-Yes]: 1
    DELETE [0-No, 1-Yes]: 0
    NOTIFY [0-No, 1-Yes]: 1

    Successfully issued request to provision ACE

### (Step 2) Onboard the client
 - start the client sample
 - Type `1` **Enter** to _Discover un-owned devices_
 - Type `3` **Enter** to _Take ownership of device_
   - Type `0` **Enter**. If you have multiple unowned devices you will have to select the correct
     device from the list.
  - Type `2` **Enter** to _Discover owned devices_ the server and client should be listed

### (Step 3) Pair Server and Client
  - Type `4` **Enter** to _Provision pair-wise credentials_
  - Type `0` **Enter** `1` **Enter** to pair the client and server. If you have multiple owned
    devices you will have to select the correct devices from the list.

### (Step 4) Restart and Test
The samples should be onboarded and provisioned. Restart the server and client they should discover
each other and run without difficulty.

Building Custom Android Applications
=================================================
These libraries and examples were built with Android API 23.  When creating a new Android project you
can choose the API level.  In building these examples, the native code libraries were copied to specific
directories in the project.  The project structure is:

```
    project/
    ├──libs/
    |  └── iotivity-lite.jar
    ├──src/
       └── main/
           ├── AndroidManifest.xml
           ├── java/
           └── jniLibs/
               ├── armeabi/
               │   └── libiotivity-lite-jni.so.so
               └── x86-64/
                   └── libiotivity-lite-jni.so.so
```

This structure is reflected in the app `build.gradle` file:

```
    android {
        .
        .
        .
        sourceSets {
            main {
                jniLibs.srcDirs = ["src/main/jniLibs", "$buildDir/native-libs"]
            }
        }
        splits {
            abi {
                enable true
                reset()
                include 'x86_64', 'armeabi'
                universalApk false
            }
        }
    }
    
    dependencies {
        compile fileTree(dir: 'libs', include: ['*.jar'])
        .
        .
        .
    }
```

To allow these example applications to work, permissions had to be granted in the `AndroidManifest.xml` file.

```
    <manifest ...>
    
        <uses-permission android:name="android.permission.INTERNET"/>
        <uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>
        <uses-permission android:name="android.permission.CHANGE_WIFI_STATE"/>
        <uses-permission android:name="android.permission.CHANGE_WIFI_MULTICAST_STATE"/>
        <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
        <uses-permission android:name="android.permission.CHANGE_NETWORK_STATE"/>
        
        <application
            .
            .
            .
        </application>
    
    </manifest>
```

Send Feedback
=================================================
Questions
[IoTivity-Lite Developer Mailing List](https://iotivity-dev@lists.iotivity.org)

Bugs
[Jira bug reporting website](https://jira.iotivity.org/projects/LITE)
