# Zephyr

## Build

### qemu_x86

```bash
mkdir ./build
cd build
source ~/zephyrproject/zephyr/zephyr-env.sh
cmake -GNinja -DBOARD=qemu_x86 -DOC_SECURITY_ENABLED=OFF -DOC_DEBUG_ENABLED=ON  -DCMAKE_BUILD_TYPE=Debug -DOC_TCP_ENABLED=OFF -DOC_IPV4_ENABLED -DOVERLAY_CONFIG="overlay-e1000.conf" ..
ninja
```

### esp32

```bash
mkdir ./build
cd build
source ~/zephyrproject/zephyr/zephyr-env.sh
cmake -GNinja -DOC_SECURITY_ENABLED=OFF -DOC_DEBUG_ENABLED=ON -DOC_TCP_ENABLED=OFF -DOC_IPV4_ENABLED=ON -DOC_REPRESENTATION_REALLOC_ENCODING_ENABLED=ON -DBOARD=esp32 ..
ninja
ninja flash
west espressif monitor
```


```bash
pkill west && kill `ps aux | grep idf_monitor.py | grep -v grep | sed "s/ [ ]*/ /g" | cut -d " " -f 2`
```
