char * device_specification = "{\
  \"device\": [\
    {\
      \"specification\": {\
        \"device\": {\
          \"deviceType\": \"oic.d.light\",\
          \"deviceName\": \"Ambience1\",\
          \"specVersion\": \"core.1.1.0\",\
          \"dataModelVersion\": \"res.1.1.0\"\
        },\
        \"platform\": {\
          \"manufacturerName\": \"fALu\",\
          \"manufacturerUrl\": \"http://www.samsung.com/sec/\",\
          \"manufacturingDate\": \"2017-08-31\",\
          \"modelNumber\": \"NWSP-01\",\
          \"platformVersion\": \"1.0\",\
          \"osVersion\": \"1.0\",\
          \"hardwareVersion\": \"1.0\",\
          \"firmwareVersion\": \"1.0\",\
          \"vendorId\": \"Ambience2019\"\
        }\
      },\
      \"resources\": {\
        \"single\": [\
          {\
            \"uri\": \"/capability/switch/main/0\",\
            \"types\": [\
              \"x.com.st.powerswitch\"\
            ],\
            \"interfaces\": [\
              \"oic.if.a\",\
              \"oic.if.baseline\"\
            ],\
            \"policy\": 3\
          },\
          {\
            \"uri\": \"/capability/switchLevel/main/0\",\
            \"types\": [\
              \"oic.r.light.dimming\"\
            ],\
            \"interfaces\": [\
              \"oic.if.a\"\
            ],\
            \"policy\": 3\
          },\
          {\
            \"uri\": \"/capability/colorTemperature/main/0\",\
            \"types\": [\
              \"x.com.st.color.temperature\"\
            ],\
            \"interfaces\": [\
              \"oic.if.a\",\
              \"oic.if.s\",\
              \"oic.if.baseline\"\
            ],\
            \"policy\": 3\
          }\
        ]\
      }\
    }\
  ],\
  \"resourceTypes\": [\
    {\
      \"type\": \"x.com.st.powerswitch\",\
      \"properties\": [\
        {\
          \"key\": \"power\",\
          \"type\": 3,\
          \"mandatory\": true,\
          \"rw\": 3\
        }\
      ]\
    },\
    {\
      \"type\": \"oic.r.light.dimming\",\
      \"properties\": [\
        {\
          \"key\": \"dimmingSetting\",\
          \"type\": 1,\
          \"mandatory\": true,\
          \"rw\": 3\
        },\
        {\
          \"key\": \"range\",\
          \"type\": 6,\
          \"mandatory\": false,\
          \"rw\": 1\
        },\
        {\
          \"key\": \"step\",\
          \"type\": 1,\
          \"mandatory\": false,\
          \"rw\": 1\
        }\
      ]\
    },\
    {\
      \"type\": \"x.com.st.color.temperature\",\
      \"properties\": [\
        {\
          \"key\": \"ct\",\
          \"type\": 1,\
          \"mandatory\": true,\
          \"rw\": 3\
        },\
        {\
          \"key\": \"range\",\
          \"type\": 6,\
          \"mandatory\": true,\
          \"rw\": 1\
        }\
      ]\
    }\
  ],\
  \"configuration\": {\
    \"easySetup\": {\
      \"connectivity\": {\
        \"type\": 1,\
        \"softAP\": {\
          \"setupId\": \"001\",\
          \"artik\": false\
        }\
      },\
      \"ownershipTransferMethod\": 0\
    },\
    \"wifi\": {\
      \"interfaces\": 15,\
      \"frequency\": 1\
    },\
    \"filePath\": {\
      \"svrdb\": \"artikserversecured.dat\",\
      \"provisioning\": \"provisioning.dat\",\
      \"certificate\": \"deviceKey.pem\",\
      \"privateKey\": \"keyFileName.der\"\
    }\
  }\
}";
